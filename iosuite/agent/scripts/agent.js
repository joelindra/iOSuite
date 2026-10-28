/**
 * iOSuite Trace - Unified Dynamic Instrumentation Agent
 * Injected into target iOS process via Frida
 * Supports both high-level Frida ObjC runtime and native libobjc ABI fallback
 */

'use strict';

(function () {
    var hasObjCBridge = (typeof ObjC !== 'undefined' && ObjC.available);
    var appOnlyFilter = false;

    // Resolve native helpers with Frida 17+ and module-specific support
    var findExport = function (modOrFunc, funcName) {
        var modName = funcName ? modOrFunc : null;
        var name = funcName ? funcName : modOrFunc;
        if (modName) {
            try {
                var mod = Process.getModuleByName(modName);
                if (mod) {
                    var p = mod.findExportByName(name);
                    if (p) return p;
                }
            } catch (e) {
                try {
                    var mod2 = Process.findModuleByName(modName);
                    if (mod2) {
                        var p2 = mod2.findExportByName(name);
                        if (p2) return p2;
                    }
                } catch (e2) {}
            }
        }
        if (typeof Module.findExportByName === 'function') {
            try {
                var p3 = Module.findExportByName(modName, name);
                if (p3) return p3;
            } catch (e3) {}
        }
        if (typeof Module.findGlobalExportByName === 'function') {
            try {
                var p4 = Module.findGlobalExportByName(name);
                if (p4) return p4;
            } catch (e4) {}
        }
        return null;
    };

    var ptr_sel_getName = findExport('sel_getName');
    var ptr_class_getName = findExport('class_getName');
    var ptr_object_getClass = findExport('object_getClass');
    var ptr_sel_registerName = findExport('sel_registerName');
    var ptr_objc_msgSend = findExport('objc_msgSend');
    var ptr_class_getMethodImplementation = findExport('class_getMethodImplementation');
    var ptr_objc_copyClassList = findExport('objc_copyClassList');
    var ptr_objc_getClass = findExport('objc_getClass');
    var ptr_class_copyMethodList = findExport('class_copyMethodList');
    var ptr_method_getName = findExport('method_getName');
    var ptr_method_getImplementation = findExport('method_getImplementation');
    var ptr_class_getInstanceMethod = findExport('class_getInstanceMethod');
    var ptr_objc_msgForward = findExport('_objc_msgForward');
    var ptr_free = findExport('free');

    var fn_sel_getName = ptr_sel_getName ? new NativeFunction(ptr_sel_getName, 'pointer', ['pointer']) : null;
    var fn_class_getName = ptr_class_getName ? new NativeFunction(ptr_class_getName, 'pointer', ['pointer']) : null;
    var fn_object_getClass = ptr_object_getClass ? new NativeFunction(ptr_object_getClass, 'pointer', ['pointer']) : null;
    var fn_sel_registerName = ptr_sel_registerName ? new NativeFunction(ptr_sel_registerName, 'pointer', ['pointer']) : null;
    var fn_objc_msgSend = ptr_objc_msgSend ? new NativeFunction(ptr_objc_msgSend, 'pointer', ['pointer', 'pointer', 'pointer']) : null;
    var fn_class_getMethodImplementation = ptr_class_getMethodImplementation ? new NativeFunction(ptr_class_getMethodImplementation, 'pointer', ['pointer', 'pointer']) : null;
    var fn_class_getInstanceMethod = ptr_class_getInstanceMethod ? new NativeFunction(ptr_class_getInstanceMethod, 'pointer', ['pointer', 'pointer']) : null;
    var fn_objc_copyClassList = ptr_objc_copyClassList ? new NativeFunction(ptr_objc_copyClassList, 'pointer', ['pointer']) : null;
    var fn_objc_getClass = ptr_objc_getClass ? new NativeFunction(ptr_objc_getClass, 'pointer', ['pointer']) : null;
    var fn_class_copyMethodList = ptr_class_copyMethodList ? new NativeFunction(ptr_class_copyMethodList, 'pointer', ['pointer', 'pointer']) : null;
    var fn_method_getName = ptr_method_getName ? new NativeFunction(ptr_method_getName, 'pointer', ['pointer']) : null;
    var fn_method_getImplementation = ptr_method_getImplementation ? new NativeFunction(ptr_method_getImplementation, 'pointer', ['pointer']) : null;
    var fn_free = ptr_free ? new NativeFunction(ptr_free, 'void', ['pointer']) : null;

    function isValidPointer(p) {
        if (!p || p.isNull()) return false;
        try {
            if (p.compare(ptr('0x100000')) < 0) return false;
            return true;
        } catch (e) {
            return false;
        }
    }

    function safeReadString(ptrVal) {
        if (!isValidPointer(ptrVal)) return '';
        try {
            return ptrVal.readUtf8String() || '';
        } catch (e) {
            try {
                return ptrVal.readCString() || '';
            } catch (e2) {
                return '';
            }
        }
    }

    function readNsStr(p) {
        if (!isValidPointer(p) || !fn_objc_msgSend || !fn_sel_registerName) return '';
        try {
            var selUtf8 = fn_sel_registerName(Memory.allocUtf8String('UTF8String'));
            var c = fn_objc_msgSend(p, selUtf8);
            if (isValidPointer(c)) return safeReadString(c);
        } catch (e) {}
        return '';
    }

    function getClassName(objPtr) {
        if (!objPtr || objPtr.isNull()) return 'nil';
        if (hasObjCBridge) {
            try { return new ObjC.Object(objPtr).$className; } catch (e) {}
        }
        if (fn_object_getClass && fn_class_getName) {
            try {
                var cls = fn_object_getClass(objPtr);
                if (cls && !cls.isNull()) {
                    var namePtr = fn_class_getName(cls);
                    var s = safeReadString(namePtr);
                    if (s) return s;
                }
            } catch (e) {}
        }
        return '0x' + objPtr.toString(16);
    }

    function getSelectorName(selPtr) {
        if (!selPtr || selPtr.isNull()) return 'nil';
        if (hasObjCBridge) {
            try { return ObjC.selectorAsString(selPtr); } catch (e) {}
        }
        if (fn_sel_getName) {
            try {
                var namePtr = fn_sel_getName(selPtr);
                var s = safeReadString(namePtr);
                if (s) return s;
            } catch (e) {}
        }
        return '0x' + selPtr.toString(16);
    }

    var mainModule = Process.mainModule;
    var mainBase = mainModule ? mainModule.base : ptr(0);
    var mainExeName = mainModule ? mainModule.name : 'TargetApp';
    var mainPath = mainModule ? mainModule.path : '';
    var appBundleDir = '';
    if (mainPath) {
        var appIdx = mainPath.indexOf('.app');
        if (appIdx !== -1) {
            appBundleDir = mainPath.substring(0, appIdx + 4);
        } else {
            appBundleDir = mainPath.substring(0, mainPath.lastIndexOf('/'));
        }
    }

    function isAppAddress(addr) {
        if (!addr || addr.isNull()) return false;
        var mod = null;
        try {
            if (typeof Process.findModuleByAddress === 'function') {
                mod = Process.findModuleByAddress(addr);
            } else if (typeof Process.getModuleByAddress === 'function') {
                mod = Process.getModuleByAddress(addr);
            }
        } catch (e) {}
        if (!mod) return false;
        if (!mod.path) return mod.name === mainExeName;
        // Check if located in application bundle or embedded frameworks
        if (appBundleDir && mod.path.indexOf(appBundleDir) !== -1) return true;
        if (mod.path.indexOf('.app/') !== -1) return true;
        return mod.name === mainExeName;
    }

    function resolveHandlerLocation(targetPtr, selPtr, fallbackAddr) {
        var impl = fallbackAddr;
        try {
            if (targetPtr && !targetPtr.isNull() && selPtr && !selPtr.isNull() && fn_object_getClass && fn_class_getMethodImplementation) {
                var cls = fn_object_getClass(targetPtr);
                if (cls && !cls.isNull()) {
                    var methodImp = fn_class_getMethodImplementation(cls, selPtr);
                    if (methodImp && !methodImp.isNull()) {
                        impl = methodImp;
                    }
                }
            }
        } catch (e) {}

        var mod = null;
        try { mod = Process.findModuleByAddress(impl); } catch (e) {}

        return {
            implementation: impl.toString(),
            moduleName: mod ? mod.name : 'Unknown',
            moduleBase: mod ? mod.base.toString() : '0x0',
            offset: mod ? impl.sub(mod.base).toString() : '0x0',
            isApp: isAppAddress(impl),
            disassembly: readDisassembly(impl, 8)
        };
    }

    function captureBacktrace(context) {
        var rawFrames = [];
        try {
            rawFrames = Thread.backtrace(context, Backtracer.ACCURATE);
        } catch (e) {
            try {
                rawFrames = Thread.backtrace(context, Backtracer.FUZZY);
            } catch (err) {}
        }

        var frames = [];
        var hasAppFrame = false;

        for (var i = 0; i < rawFrames.length; i++) {
            var addr = rawFrames[i];
            var sym = DebugSymbol.fromAddress(addr);
            var mod = null;
            try {
                if (typeof Process.findModuleByAddress === 'function') {
                    mod = Process.findModuleByAddress(addr);
                }
            } catch (e) {}

            var isApp = isAppAddress(addr);
            if (isApp) hasAppFrame = true;

            frames.push({
                index: i,
                address: addr.toString(),
                moduleName: mod ? mod.name : 'Unknown',
                moduleBase: mod ? mod.base.toString() : '0x0',
                offset: mod ? addr.sub(mod.base).toString() : '0x0',
                symbol: sym ? sym.name : '',
                file: sym ? sym.fileName : '',
                line: sym ? sym.lineNumber : 0,
                isApp: isApp
            });
        }

        return {
            frames: frames,
            hasAppFrame: hasAppFrame
        };
    }

    function readDisassembly(addr, count) {
        if (!addr || addr.isNull()) return [];
        var result = [];
        var current = addr;
        var limit = count || 10;

        for (var i = 0; i < limit; i++) {
            try {
                var insn = Instruction.parse(current);
                result.push({
                    address: insn.address.toString(),
                    mnemonic: insn.mnemonic,
                    opStr: insn.opStr,
                    size: insn.size
                });
                current = insn.next;
            } catch (err) {
                break;
            }
        }
        return result;
    }

    function emitEvent(event) {
        if (appOnlyFilter && event && event.location && event.location.isApp === false) {
            return;
        }
        send({
            type: 'event',
            payload: event
        });
    }

    // Lightweight Direct-Method Objective-C Instrumentation
    // Supports both Frida ObjC bridge and native libobjc fallback for Frida 17+
    // Avoids ApiResolver('objc') mass-scan which triggers memory integrity watchdogs in TikTok / anti-cheat apps.
    function hookClassMethod(className, selName, category, actionType, onEnterCallback) {
        var cleanSel = selName.replace(/^[-+]\s*/, '').trim();
        var impl = null;
        if (hasObjCBridge) {
            try {
                var cls = ObjC.classes[className];
                if (cls && cls[selName] && cls[selName].implementation) {
                    impl = cls[selName].implementation;
                }
            } catch (e) {}
        }
        if (!impl && fn_objc_getClass && fn_sel_registerName && fn_class_getMethodImplementation) {
            try {
                var c = fn_objc_getClass(Memory.allocUtf8String(className));
                if (c && !c.isNull()) {
                    var s = fn_sel_registerName(Memory.allocUtf8String(cleanSel));
                    var mImpl = fn_class_getMethodImplementation(c, s);
                    if (mImpl && !mImpl.isNull()) {
                        impl = mImpl;
                    }
                }
            } catch (e2) {}
        }
        if (!impl || impl.isNull()) return false;
        try {
            Interceptor.attach(impl, {
                onEnter: function (args) {
                    try {
                        onEnterCallback.call(this, args, impl);
                    } catch (err) {}
                }
            });
            return true;
        } catch (e3) {
            return false;
        }
    }

    function installLightweightObjCHooks() {
        hasObjCBridge = (typeof ObjC !== 'undefined' && ObjC.available);

        // 1. UI Action: UIApplication sendAction:to:from:forEvent:
        hookClassMethod('UIApplication', '- sendAction:to:from:forEvent:', 'ui_action', 'sendAction', function (args, impl) {
            var action = getSelectorName(args[2]);
            var targetCls = getClassName(args[3]);
            var senderCls = getClassName(args[4]);
            var bt = captureBacktrace(this.context);
            var loc = resolveHandlerLocation(args[3], args[2], impl);
            emitEvent({
                id: 'ui_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
                timestamp: new Date().toISOString(),
                category: 'ui_action',
                actionType: 'sendAction',
                selector: action,
                targetClass: targetCls,
                targetPointer: args[3].toString(),
                sender: { className: senderCls, pointer: args[4].toString() },
                location: loc,
                backtrace: bt,
                summary: senderCls + ' -> ' + action
            });
        });

        // 2. UI Control: UIControl sendAction:to:forEvent:
        hookClassMethod('UIControl', '- sendAction:to:forEvent:', 'ui_action', 'controlAction', function (args, impl) {
            var action = getSelectorName(args[2]);
            var targetCls = getClassName(args[3]);
            var senderCls = getClassName(args[0]);
            var bt = captureBacktrace(this.context);
            var loc = resolveHandlerLocation(args[3], args[2], impl);
            emitEvent({
                id: 'ui_ctrl_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
                timestamp: new Date().toISOString(),
                category: 'ui_action',
                actionType: 'controlAction',
                selector: action,
                targetClass: targetCls,
                targetPointer: args[3].toString(),
                sender: { className: senderCls, pointer: args[0].toString() },
                location: loc,
                backtrace: bt,
                summary: senderCls + ' -> ' + action
            });
        });

        // 3. Navigation: UIViewController viewDidAppear:
        hookClassMethod('UIViewController', '- viewDidAppear:', 'navigation', 'viewDidAppear', function (args, impl) {
            var vcName = getClassName(args[0]);
            var bt = captureBacktrace(this.context);
            var loc = resolveHandlerLocation(args[0], fn_sel_registerName ? fn_sel_registerName(Memory.allocUtf8String('viewDidAppear:')) : ptr(0), impl);
            emitEvent({
                id: 'nav_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
                timestamp: new Date().toISOString(),
                category: 'navigation',
                actionType: 'viewDidAppear',
                targetClass: vcName,
                selector: 'viewDidAppear:',
                location: loc,
                backtrace: bt,
                summary: 'Screen Appear: ' + vcName
            });
        });

        // 4. Navigation: UIViewController presentViewController:animated:completion:
        hookClassMethod('UIViewController', '- presentViewController:animated:completion:', 'navigation', 'presentModal', function (args, impl) {
            var presenter = getClassName(args[0]);
            var presented = getClassName(args[2]);
            var bt = captureBacktrace(this.context);
            var mod = null;
            try { mod = Process.findModuleByAddress(impl); } catch (e) {}
            emitEvent({
                id: 'modal_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
                timestamp: new Date().toISOString(),
                category: 'navigation',
                actionType: 'presentModal',
                targetClass: presented,
                selector: 'presentViewController:animated:completion:',
                location: {
                    implementation: impl.toString(),
                    moduleName: mod ? mod.name : 'UIKitCore',
                    moduleBase: mod ? mod.base.toString() : '0x0',
                    offset: mod ? impl.sub(mod.base).toString() : '0x0',
                    isApp: isAppAddress(impl),
                    disassembly: readDisassembly(impl, 6)
                },
                backtrace: bt,
                summary: 'Modal Present -> ' + presented
            });
        });

        // 5. Navigation: UINavigationController pushViewController:animated:
        hookClassMethod('UINavigationController', '- pushViewController:animated:', 'navigation', 'pushViewController', function (args, impl) {
            var pushedVC = getClassName(args[2]);
            var bt = captureBacktrace(this.context);
            var mod = null;
            try { mod = Process.findModuleByAddress(impl); } catch (e) {}
            emitEvent({
                id: 'push_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
                timestamp: new Date().toISOString(),
                category: 'navigation',
                actionType: 'pushViewController',
                targetClass: pushedVC,
                selector: 'pushViewController:animated:',
                location: {
                    implementation: impl.toString(),
                    moduleName: mod ? mod.name : 'UIKitCore',
                    moduleBase: mod ? mod.base.toString() : '0x0',
                    offset: mod ? impl.sub(mod.base).toString() : '0x0',
                    isApp: isAppAddress(impl),
                    disassembly: readDisassembly(impl, 6)
                },
                backtrace: bt,
                summary: 'Push Nav -> ' + pushedVC
            });
        });

        // 6. Deep Links: UIApplication openURL:options:completionHandler:
        hookClassMethod('UIApplication', '- openURL:options:completionHandler:', 'navigation', 'openURL', function (args, impl) {
            var urlStr = 'URL';
            var nsUrl = args[2];
            if (nsUrl && !nsUrl.isNull()) {
                try {
                    if (hasObjCBridge) {
                        urlStr = new ObjC.Object(nsUrl).absoluteString().toString();
                    } else if (fn_objc_msgSend && fn_sel_registerName) {
                        var selAbs = fn_sel_registerName(Memory.allocUtf8String('absoluteString'));
                        var selUtf8 = fn_sel_registerName(Memory.allocUtf8String('UTF8String'));
                        var absObj = fn_objc_msgSend(nsUrl, selAbs);
                        if (absObj && !absObj.isNull()) {
                            var cstr = fn_objc_msgSend(absObj, selUtf8);
                            if (cstr && !cstr.isNull()) urlStr = safeReadString(cstr);
                        }
                    }
                } catch (e) {}
            }
            var bt = captureBacktrace(this.context);
            var mod = null;
            try { mod = Process.findModuleByAddress(impl); } catch (e) {}
            emitEvent({
                id: 'url_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
                timestamp: new Date().toISOString(),
                category: 'navigation',
                actionType: 'openURL',
                targetClass: 'UIApplication',
                selector: 'openURL:options:completionHandler:',
                location: {
                    implementation: impl.toString(),
                    moduleName: mod ? mod.name : 'UIKitCore',
                    moduleBase: mod ? mod.base.toString() : '0x0',
                    offset: mod ? impl.sub(mod.base).toString() : '0x0',
                    isApp: isAppAddress(impl),
                    disassembly: readDisassembly(impl, 6)
                },
                backtrace: bt,
                summary: 'Open URL: ' + urlStr
            });
        });

        // 7. WebKit Script Message Handlers (WKScriptMessageHandler interception)
        installWebKitHooks();

        // 8. Network Requests (NSURLSessionTask resume interception)
        installNetworkHooks();
    }

    function installNetworkHooks() {
        if (!fn_objc_getClass || !fn_sel_registerName || !fn_class_getMethodImplementation) return;
        try {
            var cTask = fn_objc_getClass(Memory.allocUtf8String('NSURLSessionTask'));
            if (!cTask || cTask.isNull()) return;
            var sResume = fn_sel_registerName(Memory.allocUtf8String('resume'));
            var impResume = fn_class_getMethodImplementation(cTask, sResume);
            if (!impResume || impResume.isNull()) return;

            var selCurrentReq = fn_sel_registerName(Memory.allocUtf8String('currentRequest'));
            var selOrigReq = fn_sel_registerName(Memory.allocUtf8String('originalRequest'));
            var selURL = fn_sel_registerName(Memory.allocUtf8String('URL'));
            var selAbsStr = fn_sel_registerName(Memory.allocUtf8String('absoluteString'));
            var selMethod = fn_sel_registerName(Memory.allocUtf8String('HTTPMethod'));

            Interceptor.attach(impResume, {
                onEnter: function (args) {
                    try {
                        var task = args[0];
                        if (!isValidPointer(task)) return;
                        var req = fn_objc_msgSend(task, selCurrentReq);
                        if (!isValidPointer(req)) req = fn_objc_msgSend(task, selOrigReq);
                        if (!isValidPointer(req)) return;

                        var urlObj = fn_objc_msgSend(req, selURL);
                        var urlStr = '';
                        if (isValidPointer(urlObj)) {
                            var absObj = fn_objc_msgSend(urlObj, selAbsStr);
                            urlStr = readNsStr(absObj);
                        }
                        var mObj = fn_objc_msgSend(req, selMethod);
                        var method = readNsStr(mObj) || 'GET';

                        if (urlStr) {
                            var host = '';
                            var path = '';
                            var uMatch = urlStr.match(/^https?:\/\/([^\/\?#]+)(.*)$/i);
                            if (uMatch) {
                                host = uMatch[1];
                                path = uMatch[2] || '/';
                            } else {
                                host = urlStr;
                                path = '/';
                            }

                            var shortPath = path.length > 60 ? path.substring(0, 57) + '...' : path;
                            var summaryStr = 'HTTP ' + method + ': ' + urlStr;

                            var mod = null;
                            try { mod = Process.findModuleByAddress(impResume); } catch (e) {}

                            emitEvent({
                                id: 'http_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
                                timestamp: new Date().toISOString(),
                                category: 'network_trigger',
                                actionType: 'httpRequest',
                                selector: method + ' ' + shortPath,
                                targetClass: host,
                                targetPointer: task.toString(),
                                location: {
                                    implementation: impResume.toString(),
                                    moduleName: mod ? mod.name : 'CFNetwork',
                                    moduleBase: mod ? mod.base.toString() : '0x0',
                                    offset: mod ? impResume.sub(mod.base).toString() : '0x0',
                                    isApp: false,
                                    disassembly: []
                                },
                                backtrace: [],
                                summary: summaryStr
                            });
                        }
                    } catch (e) {}
                }
            });
        } catch (e) {}
    }

    function installWebKitHooks() {
        if (!fn_objc_getClass || !fn_sel_registerName || !fn_class_getMethodImplementation) return;
        try {
            var cUCC = fn_objc_getClass(Memory.allocUtf8String('WKUserContentController'));
            if (!cUCC || cUCC.isNull()) return;

            var regSels = [
                'addScriptMessageHandler:name:',
                'addScriptMessageHandler:contentWorld:name:',
                'addScriptMessageHandlerWithReply:name:',
                'addScriptMessageHandlerWithReply:contentWorld:name:'
            ];

            var hookedHandlers = {};
            var selRecv = fn_sel_registerName(Memory.allocUtf8String('userContentController:didReceiveScriptMessage:'));
            var selName = fn_sel_registerName(Memory.allocUtf8String('name'));
            var selBody = fn_sel_registerName(Memory.allocUtf8String('body'));
            var selWv = fn_sel_registerName(Memory.allocUtf8String('webView'));
            var selUrl = fn_sel_registerName(Memory.allocUtf8String('URL'));
            var selAbs = fn_sel_registerName(Memory.allocUtf8String('absoluteString'));
            var selUtf8 = fn_sel_registerName(Memory.allocUtf8String('UTF8String'));
            var selDesc = fn_sel_registerName(Memory.allocUtf8String('description'));

            function readNsStr(p) {
                if (!p || p.isNull() || !fn_objc_msgSend) return '';
                try {
                    var c = fn_objc_msgSend(p, selUtf8);
                    if (c && !c.isNull()) return safeReadString(c);
                } catch (e) {}
                return '';
            }

            function readNsDesc(p) {
                if (!p || p.isNull() || !fn_objc_msgSend) return 'nil';
                try {
                    var d = fn_objc_msgSend(p, selDesc);
                    var s = readNsStr(d);
                    if (s) return s;
                } catch (e) {}
                return '0x' + p.toString(16);
            }

            function hookHandlerClass(hCls) {
                if (!isValidPointer(hCls)) return;
                var cname = getClassName(hCls);
                if (hookedHandlers[cname]) return;
                hookedHandlers[cname] = true;

                if (fn_class_getInstanceMethod) {
                    var m = fn_class_getInstanceMethod(hCls, selRecv);
                    if (!isValidPointer(m)) return;
                }

                var mImpl = null;
                try {
                    mImpl = fn_class_getMethodImplementation(hCls, selRecv);
                } catch (e) {}
                if (!isValidPointer(mImpl)) return;
                if (ptr_objc_msgForward && mImpl.equals(ptr_objc_msgForward)) return;

                Interceptor.attach(mImpl, {
                    onEnter: function (args) {
                        var msg = args[3];
                        var hName = '';
                        var body = '';
                        var url = '';
                        if (isValidPointer(msg)) {
                            try { hName = readNsStr(fn_objc_msgSend(msg, selName)); } catch (e) {}
                            try { body = readNsDesc(fn_objc_msgSend(msg, selBody)); } catch (e) {}
                            try {
                                var wv = fn_objc_msgSend(msg, selWv);
                                if (isValidPointer(wv)) {
                                    var u = fn_objc_msgSend(wv, selUrl);
                                    if (isValidPointer(u)) url = readNsStr(fn_objc_msgSend(u, selAbs));
                                }
                            } catch (e) {}
                        }
                        var summaryStr = 'WKMessage: ' + (hName || cname) + ' (' + (body.length > 80 ? body.substring(0, 77) + '...' : body) + ')';
                        emitEvent({
                            id: 'wmsg_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
                            timestamp: new Date().toISOString(),
                            category: 'network_trigger',
                            actionType: 'scriptMessage',
                            selector: hName || 'WKScriptMessage',
                            targetClass: cname + (url ? ' • ' + url : ''),
                            targetPointer: args[0].toString(),
                            location: {
                                implementation: mImpl.toString(),
                                moduleName: 'WebKit',
                                moduleBase: '0x0',
                                offset: '0x0',
                                isApp: false,
                                disassembly: []
                            },
                            backtrace: [],
                            summary: summaryStr
                        });
                    }
                });
            }

            regSels.forEach(function (sName) {
                var s = fn_sel_registerName(Memory.allocUtf8String(sName));
                var imp = fn_class_getMethodImplementation(cUCC, s);
                if (imp && !imp.isNull()) {
                    Interceptor.attach(imp, {
                        onEnter: function (args) {
                            var handlerObj = args[2];
                            if (isValidPointer(handlerObj) && fn_object_getClass) {
                                try {
                                    var hCls = fn_object_getClass(handlerObj);
                                    if (isValidPointer(hCls)) hookHandlerClass(hCls);
                                } catch (e) {}
                            }
                        }
                    });
                }
            });
        } catch (e) {}
    }

    setTimeout(installLightweightObjCHooks, 500);

    // Dynamic Bypass Assistant States & Hooks (Integrated from iosf-ng universal bypass)
    var activeBypasses = {
        sslPinning: true,
        jailbreak: true
    };

    // 0. Anti-Debugging & Anti-Tamper Core (Essential for TikTok, banking & protected apps)
    // Intercepts ptrace (PT_DENY_ATTACH = 31) to prevent app from killing itself when attached
    try {
        var pPtrace = findExport('ptrace');
        if (pPtrace) {
            Interceptor.attach(pPtrace, {
                onEnter: function (args) {
                    this.req = args[0].toInt32();
                },
                onLeave: function (retval) {
                    if (this.req === 31) {
                        // PT_DENY_ATTACH: spoof return value to 0 so app believes it disabled debugging
                        retval.replace(ptr(0));
                    }
                }
            });
        }
    } catch (e) {}

    // 1. SecTrustEvaluateWithError (Security.framework - iOS 12+)
    try {
        var pSecTrustEvaluateWithError = findExport('Security', 'SecTrustEvaluateWithError');
        if (pSecTrustEvaluateWithError) {
            Interceptor.attach(pSecTrustEvaluateWithError, {
                onEnter: function (args) {
                    this.errorPtr = args[1];
                },
                onLeave: function (retval) {
                    if (activeBypasses.sslPinning) {
                        if (this.errorPtr && !this.errorPtr.isNull()) {
                            try {
                                this.errorPtr.writePointer(NULL);
                            } catch (err) {}
                        }
                        retval.replace(ptr(1));
                    }
                }
            });
        }
    } catch (e) {}

    // 2. SecTrustEvaluate (Security.framework - Legacy & High-Level APIs)
    try {
        var pSecTrustEvaluate = findExport('Security', 'SecTrustEvaluate');
        if (pSecTrustEvaluate) {
            Interceptor.attach(pSecTrustEvaluate, {
                onEnter: function (args) {
                    this.resultPtr = args[1];
                },
                onLeave: function (retval) {
                    if (activeBypasses.sslPinning) {
                        if (this.resultPtr && !this.resultPtr.isNull()) {
                            try {
                                this.resultPtr.writeU32(1); // kSecTrustResultProceed = 1
                            } catch (err) {}
                        }
                        retval.replace(ptr(0)); // errSecSuccess = 0
                    }
                }
            });
        }
    } catch (e) {}

    // 3. SecTrustGetTrustResult (Security.framework)
    try {
        var pSecTrustGetTrustResult = findExport('Security', 'SecTrustGetTrustResult');
        if (pSecTrustGetTrustResult) {
            Interceptor.attach(pSecTrustGetTrustResult, {
                onEnter: function (args) {
                    this.resultPtr = args[1];
                },
                onLeave: function (retval) {
                    if (activeBypasses.sslPinning) {
                        if (this.resultPtr && !this.resultPtr.isNull()) {
                            try {
                                this.resultPtr.writeU32(1); // kSecTrustResultProceed = 1
                            } catch (err) {}
                        }
                        retval.replace(ptr(0)); // errSecSuccess = 0
                    }
                }
            });
        }
    } catch (e) {}

    // 4. Universal BoringSSL Custom Verify Callbacks (libboringssl.dylib & bundled app modules like TikTok boringssl)
    var replacedCallbacks = {};
    var hookedBoringModules = {};

    function hookBoringCallback(cb) {
        if (!cb || cb.isNull()) return;
        var key = cb.toString();
        if (replacedCallbacks[key]) return;
        replacedCallbacks[key] = true;
        try {
            Interceptor.attach(cb, {
                onLeave: function (retval) {
                    if (activeBypasses.sslPinning) {
                        var orig = retval.toInt32();
                        // BoringSSL enum ssl_verify_result_t:
                        // 0 = ssl_verify_ok
                        // 1 = ssl_verify_invalid
                        // 2 = ssl_verify_retry
                        // Only coerce ssl_verify_invalid (1) to ssl_verify_ok (0).
                        // Leaving ssl_verify_retry (2) intact is critical to avoid
                        // corrupting asynchronous TLS 1.3 handshakes.
                        if (orig === 1) {
                            retval.replace(ptr(0)); // 0 = ssl_verify_ok in BoringSSL
                        }
                    }
                }
            });
        } catch (err) {}
    }

    function hookBoringModule(modName) {
        if (!modName || hookedBoringModules[modName]) return;
        try {
            var mod = Process.findModuleByName(modName);
            if (!mod) return;
            hookedBoringModules[modName] = true;

            ['SSL_set_custom_verify', 'SSL_CTX_set_custom_verify'].forEach(function (exportName) {
                try {
                    var pVerify = mod.findExportByName(exportName);
                    if (pVerify) {
                        Interceptor.attach(pVerify, {
                            onEnter: function (args) {
                                hookBoringCallback(args[2]);
                            }
                        });
                    }
                } catch (e) {}
            });

            var sslHostMap = {};

            // Intercept SNI to record target domain in interception log
            try {
                var pSni = mod.findExportByName('SSL_set_tlsext_host_name');
                if (pSni) {
                    Interceptor.attach(pSni, {
                        onEnter: function (args) {
                            try {
                                var host = args[1].readUtf8String();
                                if (host) {
                                    sslHostMap[args[0].toString()] = host;
                                    emitEvent({
                                        id: 'tls_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
                                        timestamp: new Date().toISOString(),
                                        category: 'network_trigger',
                                        actionType: 'tlsHandshake',
                                        selector: host,
                                        targetClass: 'BoringSSL (TLS SNI)',
                                        targetPointer: args[0].toString(),
                                        location: {
                                            implementation: ptr(pSni).toString(),
                                            moduleName: modName,
                                            moduleBase: mod.base.toString(),
                                            offset: ptr(pSni).sub(mod.base).toString(),
                                            isApp: false,
                                            disassembly: []
                                        },
                                        backtrace: [],
                                        summary: 'TLS SNI: ' + host + ' (' + modName + ')'
                                    });
                                }
                            } catch (e) {}
                        }
                    });
                }
            } catch (e) {}

            // Intercept plaintext HTTP/1.1 and HTTP/2 requests directly above TLS
            try {
                var pWrite = mod.findExportByName('SSL_write');
                if (pWrite) {
                    Interceptor.attach(pWrite, {
                        onEnter: function (args) {
                            try {
                                var len = args[2].toInt32();
                                if (len > 0) {
                                    var maxRead = Math.min(len, 512);
                                    var rawBuf = args[1].readByteArray(maxRead);
                                    if (!rawBuf) return;
                                    var u8 = new Uint8Array(rawBuf);
                                    var text = '';
                                    for (var i = 0; i < u8.length; i++) {
                                        var c = u8[i];
                                        text += (c >= 32 && c <= 126) ? String.fromCharCode(c) : ' ';
                                    }

                                    var method = '';
                                    var path = '';
                                    var mMatch = text.match(/\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s\r\n]+)/);
                                    if (mMatch) {
                                        method = mMatch[1];
                                        path = mMatch[2];
                                    } else {
                                        var pMatch = text.match(/\b(\/(api|v\d+|ws|video|oauth|auth|account|user|profile|login|check|status|event|log|tos|feed)[^\s\r\n]*)/i);
                                        if (pMatch) {
                                            path = pMatch[1];
                                        }
                                    }

                                    if (path) {
                                        var host = sslHostMap[args[0].toString()] || modName;
                                        var summaryStr = 'API: ' + host + ' -> ' + (method ? method + ' ' : '') + path;
                                        if (summaryStr.length > 220) summaryStr = summaryStr.substring(0, 217) + '...';
                                        emitEvent({
                                            id: 'http_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
                                            timestamp: new Date().toISOString(),
                                            category: 'network_trigger',
                                            actionType: 'httpRequest',
                                            selector: 'SSL_write',
                                            targetClass: host,
                                            targetPointer: args[0].toString(),
                                            location: {
                                                implementation: ptr(pWrite).toString(),
                                                moduleName: modName,
                                                moduleBase: mod.base.toString(),
                                                offset: ptr(pWrite).sub(mod.base).toString(),
                                                isApp: false,
                                                disassembly: []
                                            },
                                            backtrace: [],
                                            summary: summaryStr
                                        });
                                    }
                                }
                            } catch (e) {}
                        }
                    });
                }
            } catch (e) {}
        } catch (e) {}
    }

    function scanAndHookBoringModules() {
        hookBoringModule('libboringssl.dylib');
        try {
            Process.enumerateModules().forEach(function (m) {
                var n = (m.name || '').toLowerCase();
                if (n.indexOf('boring') !== -1 || n.indexOf('cronet') !== -1 || n.indexOf('ttnet') !== -1 || n.indexOf('quic') !== -1) {
                    hookBoringModule(m.name);
                }
            });
        } catch (e) {}
    }

    scanAndHookBoringModules();

    try {
        var pDlopen = findExport('dlopen');
        if (pDlopen) {
            Interceptor.attach(pDlopen, {
                onLeave: function (retval) {
                    if (!retval.isNull()) {
                        scanAndHookBoringModules();
                    }
                }
            });
        }
    } catch (e) {}

    // 5. In-App Transparent Socket Redirection & QUIC Disabler
    var proxyConfig = {
        enabled: false,
        host: '192.168.50.216',
        port: 1338
    };
    var proxyIpParts = [192, 168, 50, 216];

    function updateProxyConfig(host, port, enabled) {
        if (host) proxyConfig.host = String(host).trim();
        if (port) proxyConfig.port = parseInt(port, 10) || 1338;
        proxyConfig.enabled = !!enabled;
        try {
            proxyIpParts = proxyConfig.host.split('.').map(function (x) { return parseInt(x, 10); });
        } catch (e) {
            proxyIpParts = [192, 168, 50, 216];
        }
    }

    try {
        var pConnect = findExport('connect');
        if (pConnect) {
            Interceptor.attach(pConnect, {
                onEnter: function (args) {
                    try {
                        if (!proxyConfig.enabled) return;
                        var sa = args[1];
                        if (sa.isNull()) return;
                        var fam = sa.add(1).readU8();
                        if (fam === 2) { // AF_INET
                            var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                            var ip = sa.add(4).readU8() + '.' + sa.add(5).readU8() + '.' + sa.add(6).readU8() + '.' + sa.add(7).readU8();
                            if ((port === 443 || port === 80) && ip !== proxyConfig.host && ip !== '127.0.0.1' && ip !== '0.0.0.0') {
                                // NOTE: this redirect is protocol-blind -- it moves the
                                // destination only, so a :443 socket still emits a raw TLS
                                // ClientHello with no CONNECT preposition. Burp cannot parse
                                // that. proxyConfig must therefore point at iOSuite's
                                // transparent relay (default :1338), which re-frames the
                                // stream as CONNECT / absolute-form before Burp sees it.
                                sa.add(2).writeU8((proxyConfig.port >> 8) & 0xff);
                                sa.add(3).writeU8(proxyConfig.port & 0xff);
                                sa.add(4).writeU8(proxyIpParts[0]);
                                sa.add(5).writeU8(proxyIpParts[1]);
                                sa.add(6).writeU8(proxyIpParts[2]);
                                sa.add(7).writeU8(proxyIpParts[3]);
                                emitEvent({
                                    id: 'redir_' + Date.now() + '_' + Math.floor(Math.random() * 1000),
                                    timestamp: new Date().toISOString(),
                                    category: 'network_trigger',
                                    actionType: 'socketRedirect',
                                    selector: 'connect',
                                    targetClass: 'ProxyRedirector',
                                    targetPointer: args[0].toString(),
                                    location: null,
                                    backtrace: [],
                                    summary: 'Socket Redirect: ' + ip + ':' + port + ' -> ' + proxyConfig.host + ':' + proxyConfig.port
                                });
                            }
                        }
                    } catch (e) {}
                }
            });
        }

        // QUIC (UDP 443) blocker: forces apps using Cronet/TTNet/QUIC to fallback to TCP TLS
        var pSendto = findExport('sendto');
        if (pSendto) {
            Interceptor.attach(pSendto, {
                onEnter: function (args) {
                    try {
                        if (!activeBypasses.sslPinning) return;
                        var sa = args[4];
                        if (!sa.isNull()) {
                            var fam = sa.add(1).readU8();
                            if (fam === 2) { // AF_INET
                                var port = (sa.add(2).readU8() << 8) | sa.add(3).readU8();
                                if (port === 443) {
                                    this.quicDrop = true;
                                }
                            }
                        }
                    } catch (e) {}
                },
                onLeave: function (retval) {
                    if (this.quicDrop) {
                        retval.replace(ptr(-1));
                    }
                }
            });
        }
    } catch (e) {}

    // 6. Jailbreak Detection Anti-Tamper Bypass (Filesystem check spoofing)
    var jbPaths = [
        '/Applications/Cydia.app',
        '/Applications/Sileo.app',
        '/Applications/Zebra.app',
        '/Library/MobileSubstrate',
        '/bin/bash',
        '/usr/sbin/sshd',
        '/etc/apt',
        '/var/lib/cydia',
        '/var/jb',
        '/jb'
    ];

    try {
        var pAccess = findExport('libsystem_kernel.dylib', 'access');
        if (!pAccess) pAccess = findExport('access');
        if (pAccess) {
            Interceptor.attach(pAccess, {
                onEnter: function (args) {
                    this.spoof = false;
                    if (activeBypasses.jailbreak && !args[0].isNull()) {
                        try {
                            var path = args[0].readUtf8String();
                            for (var i = 0; i < jbPaths.length; i++) {
                                if (path.indexOf(jbPaths[i]) !== -1) {
                                    this.spoof = true;
                                    break;
                                }
                            }
                        } catch (err) {}
                    }
                },
                onLeave: function (retval) {
                    if (this.spoof) {
                        retval.replace(ptr(-1));
                    }
                }
            });
        }
    } catch (e) {}

    function readMemoryHex(addrStr, size) {
        try {
            var p = ptr(addrStr);
            var sz = Math.min(Math.max(parseInt(size) || 64, 16), 512);
            var buf = p.readByteArray(sz);
            if (!buf) return { success: false, error: 'Memory unreadable at ' + addrStr };
            var u8 = new Uint8Array(buf);
            var rows = [];
            for (var i = 0; i < u8.length; i += 16) {
                var bytes = [];
                var ascii = '';
                for (var j = 0; j < 16; j++) {
                    if (i + j < u8.length) {
                        var b = u8[i + j];
                        bytes.push(b.toString(16).toUpperCase().padStart(2, '0'));
                        ascii += (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.';
                    }
                }
                var offset = '0x' + p.add(i).toString(16).toUpperCase();
                rows.push({ offset: offset, bytes: bytes, ascii: ascii });
            }
            return { success: true, address: addrStr, size: sz, rows: rows };
        } catch (e) {
            return { success: false, error: e.message };
        }
    }

    function enumerateClasses(query) {
        try {
            var q = (query || '').toLowerCase().trim();
            var matches = [];
            var totalCount = 0;

            if (fn_objc_copyClassList && fn_class_getName) {
                var countBuf = Memory.alloc(4);
                var classList = fn_objc_copyClassList(countBuf);
                totalCount = countBuf.readUInt();
                for (var i = 0; i < totalCount; i++) {
                    var cls = classList.add(i * Process.pointerSize).readPointer();
                    if (cls.isNull()) continue;
                    var namePtr = fn_class_getName(cls);
                    if (namePtr && !namePtr.isNull()) {
                        var name = safeReadString(namePtr);
                        if (name && (!q || name.toLowerCase().indexOf(q) !== -1)) {
                            matches.push(name);
                            if (matches.length >= 100) break;
                        }
                    }
                }
                if (fn_free) fn_free(classList);
            }
            return { success: true, total: totalCount, classes: matches };
        } catch (e) {
            return { success: false, error: e.message, classes: [] };
        }
    }

    function enumerateMethods(className) {
        try {
            if (!fn_objc_getClass || !fn_class_copyMethodList || !fn_method_getName || !fn_sel_getName) {
                return { success: false, error: 'ObjC runtime inspection unavailable' };
            }
            var cNameBuf = Memory.allocUtf8String(className);
            var cls = fn_objc_getClass(cNameBuf);
            if (!cls || cls.isNull()) {
                return { success: false, error: 'Class not found: ' + className };
            }
            var countBuf = Memory.alloc(4);
            var mList = fn_class_copyMethodList(cls, countBuf);
            var count = countBuf.readUInt();
            var methods = [];
            for (var i = 0; i < count; i++) {
                var m = mList.add(i * Process.pointerSize).readPointer();
                if (m.isNull()) continue;
                var sel = fn_method_getName(m);
                var imp = fn_method_getImplementation ? fn_method_getImplementation(m) : ptr(0);
                var selNamePtr = fn_sel_getName ? fn_sel_getName(sel) : null;
                var selName = safeReadString(selNamePtr);
                if (selName) {
                    methods.push({
                        selector: selName,
                        implementation: imp ? imp.toString() : '0x0'
                    });
                    if (methods.length >= 150) break;
                }
            }
            if (fn_free) fn_free(mList);
            return { success: true, className: className, total: count, methods: methods };
        } catch (e) {
            return { success: false, error: e.message, methods: [] };
        }
    }

    function evalJs(code) {
        try {
            var res = eval(code);
            return {
                success: true,
                result: (typeof res === 'object' && res !== null) ? JSON.stringify(res, null, 2) : String(res)
            };
        } catch (e) {
            return { success: false, error: e.stack || e.message };
        }
    }

    function setBypass(featureName, enabled) {
        if (featureName === 'sslPinning' || featureName === 'ssl_pinning') {
            activeBypasses.sslPinning = !!enabled;
            return { success: true, feature: 'sslPinning', state: activeBypasses.sslPinning };
        }
        if (featureName === 'jailbreak') {
            activeBypasses.jailbreak = !!enabled;
            return { success: true, feature: 'jailbreak', state: activeBypasses.jailbreak };
        }
        return { success: false, error: 'Unknown feature: ' + featureName };
    }

    function getBypasses() {
        return { success: true, bypasses: activeBypasses };
    }

    // RPC Exports
    rpc.exports = {
        getAppInfo: function () {
            return {
                executableName: mainExeName,
                baseAddress: mainBase.toString(),
                arch: Process.arch,
                pointerSize: Process.pointerSize
            };
        },
        readDisasm: function (addrStr, count) {
            try {
                return readDisassembly(ptr(addrStr), count || 10);
            } catch (e) {
                return [];
            }
        },
        readMemoryHex: readMemoryHex,
        read_memory_hex: readMemoryHex,
        enumerateClasses: enumerateClasses,
        enumerate_classes: enumerateClasses,
        enumerateMethods: enumerateMethods,
        enumerate_methods: enumerateMethods,
        evalJs: evalJs,
        eval_js: evalJs,
        setBypass: setBypass,
        set_bypass: setBypass,
        getBypasses: getBypasses,
        get_bypasses: getBypasses,
        setAppOnlyFilter: function (enabled) {
            appOnlyFilter = !!enabled;
            return { success: true, appOnlyFilter: appOnlyFilter };
        },
        set_app_only_filter: function (enabled) {
            appOnlyFilter = !!enabled;
            return { success: true, appOnlyFilter: appOnlyFilter };
        },
        getAppOnlyFilter: function () {
            return { success: true, appOnlyFilter: appOnlyFilter };
        },
        get_app_only_filter: function () {
            return { success: true, appOnlyFilter: appOnlyFilter };
        },
        setProxy: function (host, port, enabled) {
            updateProxyConfig(host, port, enabled);
            return { success: true, host: proxyConfig.host, port: proxyConfig.port, enabled: proxyConfig.enabled };
        },
        set_proxy: function (host, port, enabled) {
            updateProxyConfig(host, port, enabled);
            return { success: true, host: proxyConfig.host, port: proxyConfig.port, enabled: proxyConfig.enabled };
        },
        getProxy: function () {
            return { success: true, host: proxyConfig.host, port: proxyConfig.port, enabled: proxyConfig.enabled };
        },
        get_proxy: function () {
            return { success: true, host: proxyConfig.host, port: proxyConfig.port, enabled: proxyConfig.enabled };
        },
        invokeHandler: function (targetPtr, selector, senderPtr) {
            return this.invoke_handler(targetPtr, selector, senderPtr);
        },
        invoke_handler: function (targetPtr, selector, senderPtr) {
            try {
                if (hasObjCBridge) {
                    var obj = new ObjC.Object(ptr(targetPtr));
                    var sel = ObjC.selector(selector);
                    var senderObj = (senderPtr && senderPtr !== '0x0') ? new ObjC.Object(ptr(senderPtr)) : null;
                    ObjC.schedule(ObjC.mainQueue, function () {
                        obj.performSelector_withObject_(sel, senderObj);
                    });
                    return { success: true, message: 'Dispatched to main queue via ObjC bridge' };
                } else if (fn_objc_msgSend && fn_sel_registerName) {
                    var sel = fn_sel_registerName(Memory.allocUtf8String(selector));
                    var target = ptr(targetPtr);
                    var sender = (senderPtr && senderPtr !== '0x0') ? ptr(senderPtr) : ptr(0);
                    var ret = fn_objc_msgSend(target, sel, sender);
                    return { success: true, message: 'Invoked via native objc_msgSend', result: ret ? ret.toString() : '0x0' };
                }
                return { success: false, message: 'No invocation method available' };
            } catch (e) {
                return { success: false, message: e.message };
            }
        },
        triggerDemoEvent: function (category, actionName, targetName) {
            try {
                var cat = category || 'ui_action';
                var act = actionName || 'onFeatureTapped:';
                var tgt = targetName || mainExeName + '.MainViewController';
                var bt = captureBacktrace(null);
                var sampleAddr = mainBase.add(0x1000);
                var mod = null;
                try { mod = Process.findModuleByAddress(sampleAddr); } catch (e) {}

                emitEvent({
                    id: 'live_' + Date.now(),
                    timestamp: new Date().toISOString(),
                    category: cat,
                    actionType: 'live_interception',
                    selector: act,
                    targetClass: tgt,
                    targetPointer: sampleAddr.toString(),
                    sender: {
                        className: 'UIButton',
                        pointer: mainBase.toString(),
                        title: 'Demo Feature Trigger'
                    },
                    location: {
                        implementation: sampleAddr.toString(),
                        moduleName: mod ? mod.name : mainExeName,
                        moduleBase: mod ? mod.base.toString() : mainBase.toString(),
                        offset: '0x1000',
                        isApp: true,
                        disassembly: readDisassembly(sampleAddr, 6)
                    },
                    backtrace: bt,
                    summary: tgt + ' -> ' + act
                });
                return { success: true };
            } catch (e) {
                return { success: false, error: e.message };
            }
        }
    };

    send({
        type: 'log',
        level: 'info',
        message: 'iOSuite Trace Agent active on ' + mainExeName + ' (' + Process.arch + ')'
    });
})();
