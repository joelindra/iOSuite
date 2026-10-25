"""
Unit tests for event dispatcher, deduplication, and filtering.
"""

from iosuite.core.dispatcher import EventDispatcher


def test_dispatcher_deduplication():
    dispatcher = EventDispatcher()

    raw1 = {
        "id": "1",
        "category": "ui_action",
        "actionType": "sendAction",
        "targetClass": "CheckoutViewController",
        "selector": "onPayButtonTapped:",
        "summary": "UIButton -> onPayButtonTapped:",
    }

    # First event
    ev1 = dispatcher.process_raw_event(raw1)
    assert len(dispatcher.events) == 1
    assert ev1.hit_count == 1

    # Consecutive identical event
    raw2 = dict(raw1)
    raw2["id"] = "2"
    ev2 = dispatcher.process_raw_event(raw2)
    assert len(dispatcher.events) == 1
    assert ev2.hit_count == 2


def test_dispatcher_filtering():
    dispatcher = EventDispatcher()

    dispatcher.process_raw_event({
        "id": "1",
        "category": "ui_action",
        "actionType": "sendAction",
        "targetClass": "LoginViewController",
        "selector": "onLoginTapped:",
        "summary": "UIButton -> onLoginTapped:",
    })

    dispatcher.process_raw_event({
        "id": "2",
        "category": "deeplink",
        "actionType": "openURL",
        "targetClass": "AppDelegate",
        "summary": "Open URL: acme://promo",
    })

    # Search filter
    dispatcher.set_search_query("login")
    filtered = dispatcher.get_filtered_events()
    assert len(filtered) == 1
    assert filtered[0].target_class == "LoginViewController"

    # Category filter
    dispatcher.set_search_query("")
    dispatcher.set_category_filters({"deeplink"})
    filtered = dispatcher.get_filtered_events()
    assert len(filtered) == 1
    assert filtered[0].category == "deeplink"


def test_dispatcher_regex_and_pinning():
    dispatcher = EventDispatcher()

    e1 = dispatcher.process_raw_event({
        "id": "1",
        "category": "security_jailbreak",
        "actionType": "jailbreakDetection",
        "targetClass": "SecurityManager",
        "selector": "isJailbroken",
        "summary": "Check /bin/bash",
    })

    e2 = dispatcher.process_raw_event({
        "id": "2",
        "category": "ui_action",
        "actionType": "sendAction",
        "targetClass": "SettingsViewController",
        "selector": "onToggleSecurity:",
        "summary": "Toggle Security Switch",
    })

    # Regex search: /Security.*/
    dispatcher.set_search_query("/Security.*/")
    results = dispatcher.get_filtered_events()
    assert len(results) == 2

    # Star / Pin toggling
    assert not e1.pinned
    dispatcher.toggle_pin("1")
    assert e1.pinned

    # Filter only pinned
    dispatcher.set_search_query("")
    dispatcher.set_pinned_only(True)
    pinned_results = dispatcher.get_filtered_events()
    assert len(pinned_results) == 1
    assert pinned_results[0].id == "1"

    dispatcher.set_pinned_only(False)
    assert len(dispatcher.get_filtered_events()) == 2

