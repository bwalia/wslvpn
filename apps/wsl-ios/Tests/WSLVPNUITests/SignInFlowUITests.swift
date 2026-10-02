import XCTest

/// Drives the app against a control plane that is actually running.
///
/// This is an integration test, not a unit test, and it is deliberately not in
/// the default scheme: it needs `make dev` up, and a test that fails because
/// nobody started a database teaches nothing. What it does cover is the seam
/// the other 40 tests cannot reach — that the app talks to the real control
/// plane, registers a device, and renders what comes back.
///
///     make dev
///     make ui-test CONTROL_PLANE=http://127.0.0.1:8098
final class SignInFlowUITests: XCTestCase {
    /// Where the control plane is, when something has said.
    ///
    /// When nothing has, the app is left to use whatever it already has stored,
    /// which is how a simulator that has been pointed somewhere with
    /// `simctl spawn booted defaults write` keeps working without the test
    /// having to know about it.
    private var controlPlaneOverride: String? {
        ProcessInfo.processInfo.environment["WSL_CONTROL_PLANE"]
    }

    override func setUp() {
        continueAfterFailure = false
    }

    /// Launch, and leave the app signed out whatever the previous test did.
    ///
    /// The access token lives in the keychain, which outlives the app, so a
    /// test that assumed a fresh install passed alone and failed in a suite.
    private func launchSignedOut() -> XCUIApplication {
        let app = XCUIApplication()
        if let controlPlaneOverride {
            app.launchArguments = ["-control_plane_url", controlPlaneOverride]
        }
        app.launch()

        // Only the status screen has a sign-out, and on a phone it is below the
        // fold: an element that exists is not necessarily one that can be
        // tapped, and a List does not scroll itself to reach it.
        if app.staticTexts["tunnel-status"].waitForExistence(timeout: 10) {
            let signOut = app.buttons["sign-out"]
            for _ in 0..<6 where !(signOut.exists && signOut.isHittable) {
                app.swipeUp()
            }
            if signOut.exists && signOut.isHittable {
                signOut.tap()
            }
        }
        return app
    }

    func testSigningInShowsWhatTheControlPlaneReturned() throws {
        let app = launchSignedOut()

        let devSignIn = app.buttons["dev-sign-in"]
        XCTAssertTrue(
            devSignIn.waitForExistence(timeout: 10),
            "the developer sign-in should be offered against a loopback control plane"
        )
        devSignIn.tap()

        let status = app.staticTexts["tunnel-status"]
        XCTAssertTrue(
            status.waitForExistence(timeout: 30),
            "signing in should reach the status screen; is a control plane running?"
        )

        // Posture is collected on the device and sent with the registration, so
        // its presence here means the round trip happened.
        XCTAssertTrue(app.staticTexts["Posture"].exists, "posture section missing")

        attach(app.screenshot(), named: "signed-in")
    }

    /// Connecting cannot work here, and the app has to say why.
    ///
    /// Everything up to this point is real — the session below is one the
    /// control plane actually issued after evaluating policy. What fails is the
    /// last step, because the Simulator does not implement Network Extensions.
    /// A user who sees "The operation couldn't be completed" learns nothing;
    /// this asserts they are told what is actually going on.
    func testConnectingOnASimulatorExplainsItself() throws {
        let app = launchSignedOut()

        let devSignIn = app.buttons["dev-sign-in"]
        XCTAssertTrue(devSignIn.waitForExistence(timeout: 10), "developer sign-in missing")
        devSignIn.tap()
        XCTAssertTrue(
            app.staticTexts["tunnel-status"].waitForExistence(timeout: 30),
            "should be signed in before connecting"
        )

        // Connect stays disabled until the network list arrives, and tapping a
        // disabled button does nothing at all — which is what made this test
        // fail against an app that was working correctly.
        let connect = app.buttons["connect"]
        XCTAssertTrue(connect.waitForExistence(timeout: 10), "connect button missing")
        let enabled = NSPredicate(format: "isEnabled == true")
        expectation(for: enabled, evaluatedWith: connect)
        waitForExpectations(timeout: 20)
        connect.tap()

        let error = app.staticTexts["error-text"]
        XCTAssertTrue(
            error.waitForExistence(timeout: 20),
            "connecting should say why a tunnel cannot start here"
        )
        XCTAssertTrue(
            error.label.localizedCaseInsensitiveContains("simulator"),
            "the explanation should name the real reason; got: \(error.label)"
        )
        attach(app.screenshot(), named: "connect-on-simulator")
    }

    private func attach(_ screenshot: XCUIScreenshot, named name: String) {
        let attachment = XCTAttachment(screenshot: screenshot)
        attachment.name = name
        attachment.lifetime = .keepAlways
        add(attachment)
    }
}
