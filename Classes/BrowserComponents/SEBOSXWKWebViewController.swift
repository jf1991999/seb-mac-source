//
//  SEBOSXWKWebViewController.swift
//  SafeExamBrowser
//
//  Created by Daniel Schneider on 10.08.21.
//  Copyright (c) 2010-2025 Daniel R. Schneider, ETH Zurich, IT Services,
//  based on the original idea of Safe Exam Browser
//  by Stefan Schneider, University of Giessen
//  Project concept: Thomas Piendl, Daniel R. Schneider, Damian Buechel,
//  Dirk Bauer, Kai Reuter, Tobias Halbherr, Karsten Burger, Marco Lehre,
//  Brigitte Schmucki, Oliver Rahs. French localization: Nicolas Dunand
//
//  ``The contents of this file are subject to the Mozilla Public License
//  Version 2.0 (the "License"); you may not use this file except in
//  compliance with the License. You may obtain a copy of the License at
//  http://www.mozilla.org/MPL/
//
//  Software distributed under the License is distributed on an "AS IS"
//  basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//  License for the specific language governing rights and limitations
//  under the License.
//
//  The Original Code is Safe Exam Browser for Mac OS X.
//
//  The Initial Developer of the Original Code is Daniel R. Schneider.
//  Portions created by Daniel R. Schneider are Copyright
//  (c) 2010-2025 Daniel R. Schneider, ETH Zurich, IT Services,
//  based on the original idea of Safe Exam Browser
//  by Stefan Schneider, University of Giessen. All Rights Reserved.
//
//  Contributor(s): ______________________________________.
//

import Foundation
@preconcurrency import WebKit
import CocoaLumberjackSwift

// Blinkered offline schedule-cover HTML (OFFLINE_UNLOCK_PLAN.md chunk 2). Compiled into the signed
// binary — NOT a bundle resource or an on-disk file — so it is not kid-writable and cannot be
// replaced without replacing the whole (root-owned) app. Self-contained: inline CSS + inline JS,
// no external anything. The CSP <meta> is FIRST in <head> (a meta CSP only governs content parsed
// after it) and adds form-action 'none' + base-uri 'none' (default-src does NOT cover those, and
// navigate-to never shipped) — belt-and-braces over the URL filter, which is the real navigation
// gate. __UNTIL_MS__ is replaced with the segment's authored-end epoch (an integer) at load time.
let blinkeredOfflineCoverHTML = """
<!doctype html><html><head>
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; form-action 'none'; base-uri 'none'">
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Locked</title>
<style>
html,body{margin:0;height:100%;background:#0e1420;color:#e8edf6;font-family:-apple-system,system-ui;display:flex;align-items:center;justify-content:center}
.c{text-align:center;max-width:34em;padding:2em}.lock{font-size:64px}h1{font-size:1.6em;margin:.6em 0 .3em}p{color:#9fb0c8;line-height:1.5}#until{color:#e8edf6;font-weight:600}
</style></head><body><div class="c"><div class="lock">&#128274;</div>
<h1>Locked by your family&#8217;s schedule</h1>
<p>This device is offline right now, so the lock is following the plan your family already set.</p>
<p id="u" style="display:none">It unlocks at <span id="until"></span> &#8212; no internet needed.</p>
<script>
try{var ms=Number("__UNTIL_MS__");if(ms>0){var d=new Date(ms);
document.getElementById("until").textContent=d.toLocaleTimeString([], {hour:"numeric",minute:"2-digit"});
document.getElementById("u").style.display="block";}}catch(e){}
</script></div></body></html>
"""

public class SEBOSXWKWebViewController: NSViewController, WKUIDelegate, WKNavigationDelegate, SEBAbstractBrowserControllerDelegate, WKUIDelegatePrivateSEB {
        
    weak public var navigationDelegate: SEBAbstractWebViewNavigationDelegate?
    
    private var _sebWebView : SEBOSXWKWebView?
    private var webViewConfiguration: WKWebViewConfiguration?
    /// Serves the offline cover. SHARED, and that is load-bearing.
    ///
    /// `wkWebViewConfiguration` is a lazily-created SINGLETON — `SEBBrowserController.m:181` states
    /// it directly: "the handler is installed on the ONE shared _wkWebViewConfiguration every window
    /// is built". A per-controller handler therefore breaks: the FIRST controller to build a web view
    /// registers its instance and every later controller's instance is never registered. It is
    /// stateless now (Constraint A reads the signed config), so sharing is simply correct rather than
    /// load-bearing — but a per-controller object would still be a misleading thing to leave here.
    static let blinkeredOfflineCoverSchemeHandler = BlinkeredOfflineCoverSchemeHandler()
    private var wrapperView : NSView = NSView.init()
    
    public var sebWebView : SEBOSXWKWebView? {
        if _sebWebView == nil {
            if webViewConfiguration == nil {
                webViewConfiguration = navigationDelegate?.wkWebViewConfiguration
            }
            let fullScreenPossible = navigationDelegate?.isAACEnabled ?? false
            webViewConfiguration?.preferences._setFullScreenEnabled(fullScreenPossible)
//            webViewConfiguration?.preferences._setShouldAllowUserInstalledFonts(false) //ToDo: Test if this controls downloading fonts

            // Register the cover's scheme handler BEFORE construction: WKWebView snapshots its
            // handlers at init. Registering the same scheme twice throws, and this configuration can
            // be handed to more than one controller, so ask first.
            if webViewConfiguration?.urlSchemeHandler(forURLScheme: "blinkered-offlinecover") == nil {
                webViewConfiguration?.setURLSchemeHandler(SEBOSXWKWebViewController.blinkeredOfflineCoverSchemeHandler,
                                                          forURLScheme: "blinkered-offlinecover")
            }
            DDLogDebug("WKWebViewConfiguration \(String(describing: webViewConfiguration))")
            _sebWebView = SEBOSXWKWebView.init(frame: .zero, configuration: webViewConfiguration!)
            _sebWebView?.sebOSXWebViewController = self
            _sebWebView?.autoresizingMask = [.width, .height]
            _sebWebView?.translatesAutoresizingMaskIntoConstraints = true
            _sebWebView?.uiDelegate = self
            _sebWebView?.navigationDelegate = self
            _sebWebView?.addObserver(self, forKeyPath: #keyPath(WKWebView.title), options: .new, context: nil)
            
            // §5 C5 — the floor under every other defence. An empty WKWebView draws opaque WHITE,
            // and that white is what a parent read as "the Mac is broken" on 18 Aug. This paints
            // the empty area in the lock's own brand colour instead, so EVERY residual failure of
            // the backdrop above it — a dropped install call, a broken commit forward, a webview
            // class that does not forward, a future refactor — degrades to brand colour rather
            // than white. Self-healing by construction: the page's own background paints over it
            // the instant a document commits, so unlike the backdrop it can never cover content.
            // Value tracks +[SEBBrowserWindow blinkeredBrandBackdropColor] (#1a1a2e); that class
            // is not exposed to Swift, so the components are repeated here and both copies are
            // pinned by run-empty-content-backdrop-test.sh.
            if #available(macOS 12.0, *) {
                _sebWebView?.underPageBackgroundColor = NSColor(srgbRed: 0x1a/255.0,
                                                                green: 0x1a/255.0,
                                                                blue:  0x2e/255.0, alpha: 1.0)
            }

            _sebWebView?.customUserAgent = navigationDelegate?.customSEBUserAgent
            let enableZoomPage = UserDefaults.standard.secureBool(forKey: "org_safeexambrowser_SEB_enableZoomPage")
            _sebWebView?.allowsMagnification = enableZoomPage
            urlFilter = SEBURLFilter.shared()
            
            // Create wrapper view which is necessary for WebInspector to not flicker
            wrapperView.autoresizingMask = [.width, .height]
            wrapperView.autoresizesSubviews = true
            wrapperView.addSubview(_sebWebView!)
//            _sebWebView?.frame = wrapperView.bounds
        }
        return _sebWebView
    }
    
    public var privateClipboardEnabled = false
    public var allowDictionaryLookup = false
    public var allowPDFPlugIn = false

    public var scrollLockActive = false
    
    private var zoomScale : CGFloat?

    private var urlFilter : SEBURLFilter?
    
    convenience init(delegate: SEBAbstractWebViewNavigationDelegate, configuration: WKWebViewConfiguration?) {
        self.init()
        dynamicLogLevel = MyGlobals.ddLogLevel()
        webViewConfiguration = configuration
        navigationDelegate = delegate
    }
    
    public func closeWKWebView() {
        _sebWebView?.removeObserver(self, forKeyPath: #keyPath(WKWebView.title))
        _sebWebView?.removeFromSuperview()
        wrapperView.removeFromSuperview()
        _sebWebView = nil
    }
    
    public override func loadView() {
        view = sebWebView!
    }
    
    public override func observeValue(forKeyPath keyPath: String?, of object: Any?, change: [NSKeyValueChangeKey : Any]?, context: UnsafeMutableRawPointer?) {
        if keyPath == "title" {
            if let title = sebWebView?.title {
                self.navigationDelegate?.sebWebViewDidUpdateTitle?(title)
            }
        }
    }
    
    public override func viewWillAppear() {
        sebWebView?.uiDelegate = self
    }
    
    public override func viewWillDisappear() {
        sebWebView?.uiDelegate = nil
    }
    
    public func nativeWebView() -> Any {
        return sebWebView as Any
    }
    
    public func url() -> URL? {
        return sebWebView?.url
    }
    
    public func pageTitle() -> String? {
        return sebWebView?.title
    }
    
    public func privateCopy(_ sender: Any) {
        sebWebView?.privateCopy(sender)
    }
    
    public func privateCut(_ sender: Any) {
        sebWebView?.privateCut(sender)
    }
    
    public func privatePaste(_ sender: Any) {
        sebWebView?.privatePaste(sender)
    }
    
    public func toggleScrollLock() {
    }
    
    public func isScrollLockActive() -> Bool {
        return false
    }
    
    public func setPrivateClipboardEnabled(_ privateClipboardEnabled: Bool) {
        self.privateClipboardEnabled = privateClipboardEnabled
    }
    
    public func setAllowDictionaryLookup(_ allowDictionaryLookup: Bool) {
        _sebWebView?.allowsLinkPreview = allowDictionaryLookup
    }
    
    public func setAllowPDFPlugIn(_ allowPDFPlugIn: Bool) {
        self.allowPDFPlugIn = allowPDFPlugIn
    }
    
    public func canGoBack() -> Bool {
        return sebWebView?.canGoBack ?? false
    }
    
    public func canGoForward() -> Bool {
        return sebWebView?.canGoForward ?? false
    }
    
    public func goBack() {
        sebWebView?.goBack()
    }
    
    public func goForward() {
        sebWebView?.goForward()
    }
    
    public func clearBackForwardList() {
        sebWebView?.backForwardList.perform(Selector(("_removeAllItems")))
    }
    
    public func load(_ url: URL) {
        // Blinkered offline schedule cover (OFFLINE_UNLOCK_PLAN.md chunk 2): the agent stages an
        // offline lock whose startURL is `blinkered-offlinecover://<untilMs>`. `file://` can't be
        // used — WKWebView refuses file read access via load(URLRequest) — so the cover is a
        // COMPILED-IN string, now SERVED by a WKURLSchemeHandler rather than injected with
        // loadHTMLString. This function no longer intercepts the scheme; it loads it like any other
        // URL, and the handler authorises the request against the signed config.
        // The cover is no longer INJECTED (loadHTMLString) — it is SERVED, by
        // BlinkeredOfflineCoverSchemeHandler below, from this exact URL.
        //
        // WHY: an injected document has no URL that reproduces it, so EVERY reloader destroyed the
        // lock screen and left white with no way back — ⌘R, the context menu's Reload, the page's own
        // location.reload(), and reload() from webViewWebContentProcessDidTerminate, which needs NO
        // USER ACTION AT ALL (device-proven 11 and 12 Sep: WebKit content process killed, cover gone,
        // nobody touching the machine). Two of those never enter Swift or Objective-C, so no override
        // and no predicate could ever have caught them.
        //
        // NOTHING IS DONE HERE. The handler authorises from the signed config, not from this call —
        // see Constraint A. An earlier version armed the handler here, which page content could
        // reach.
        sebWebView?.load(URLRequest.init(url: url))
    }

    // Build the offline cover HTML from the compiled-in constant. Security-relevant choices:
    //
    //  • THE ORIGIN CHANGED, and the comment that used to sit here said "baseURL is about:blank
    //    (opaque origin) — LOAD-BEARING, do NOT change to a real origin". That instruction is
    //    superseded, and it is rewritten rather than deleted because its REASON still matters:
    //    the blinkered script-message bridge gates trusted actions (incl. setQuitPassword) on the
    //    sender frame's origin being https://blinkered.com.au (SEBBrowserController.m:160-171).
    //    A `blinkered-offlinecover://` origin fails that check exactly as an opaque origin did —
    //    driven with a real bridge message, not assumed. What the custom origin DOES gain over an
    //    opaque one is storage and same-origin-ness with other documents on the same scheme; that
    //    is contained by Constraint A, which permits exactly one URL to ever exist on it.
    //
    //  • untilMs is injected as a re-emitted INTEGER (never string interpolation) — it crosses the
    //    kid-writable .seb boundary, so it's treated as untrusted; an Int64 can only produce digits.
    //  • __UNTIL_MS__ is the ONLY interpolation into the cover; the fallback is a constant. Keep it
    //    so — any future .seb-derived string reaching this HTML would reintroduce injection.
    //  • Navigation containment is the URL filter (default-deny), NOT the CSP: the CSP blocks
    //    subresource/fetch reach; the filter blocks navigation. Both layers kept honest.
    //  • THE COVER HAS NO CLOCK. untilMs is an absolute epoch rendered once, so re-serving it after
    //    a reload shows the correct remaining time. If a future cover gains a countdown timer, that
    //    is no longer true and this comment is the warning.
    // BEGIN blinkeredCoverBody
    static func blinkeredOfflineCoverHTMLBody(for url: URL) -> String {
        let untilMs = Int64(url.host ?? "") ?? 0
        var html = blinkeredOfflineCoverHTML.replacingOccurrences(of: "__UNTIL_MS__", with: String(untilMs))
#if DEBUG
        // Rig containment harness (DEBUG builds only — never compiled into a release). The rig
        // operator triggers it by editing the staged offline-lock.seb's startURL to
        // `blinkered-offlinecover://<ms>?rigtest=1`. See docs/OFFLINE_COVER_RIG_TEST.md.
        if let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems,
           items.contains(where: { $0.name == "rigtest" }),
           let bodyEnd = html.range(of: "</body>", options: .backwards) {
            html.replaceSubrange(bodyEnd, with: blinkeredOfflineCoverRigTestJS + "</body>")
        }
#endif
        return html
    }
    // END blinkeredCoverBody
    
    public func stopLoading() {
        sebWebView?.stopLoading()
    }
 
    public func storePasteboard() {
        self.navigationDelegate?.storePasteboard?()
    }
    
    public func restorePasteboard() {
        self.navigationDelegate?.restorePasteboard?()
    }
    

    public func webView(_ webView: WKWebView, didStartProvisionalNavigation navigation: WKNavigation) {
        navigationDelegate?.webView?(webView, didStartProvisionalNavigation: navigation)
    }
    
    public func webView(_ webView: WKWebView,
                         didReceiveServerRedirectForProvisionalNavigation navigation: WKNavigation) {
        navigationDelegate?.webView?(webView, didReceiveServerRedirectForProvisionalNavigation: navigation)
    }
    
    public func webView(_ webView: WKWebView, didFailProvisionalNavigation navigation: WKNavigation, withError error: Error) {
        navigationDelegate?.webView?(webView, didFailProvisionalNavigation: navigation, withError: error)
    }
    
    public func webView(_ webView: WKWebView,
                        didReceive challenge: URLAuthenticationChallenge,
                        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        navigationDelegate?.webView?(webView, didReceive: challenge, completionHandler: completionHandler)
    }
    
    public func webView(_ webView: WKWebView,
                          didCommit navigation: WKNavigation) {
        navigationDelegate?.webView?(webView, didCommit: navigation)
    }
    
    public func webView(_ webView: WKWebView, didFinish navigation: WKNavigation) {
        navigationDelegate?.webView?(webView, didFinish: navigation)
    }
    
    public func webView(_ webView: WKWebView, didFail navigation: WKNavigation, withError error: Error) {
        navigationDelegate?.sebWebViewDidFailLoadWithError?(error)
    }
    
    public func webViewWebContentProcessDidTerminate(_ webView: WKWebView) {
        DDLogError("[SEBOSXWKWebViewController webViewWebContentProcessDidTerminate:\(webView)]")
        navigationDelegate?.webViewWebContentProcessDidTerminate?(webView)
    }

    public func webView(_ webView: WKWebView, decidePolicyFor navigationAction: WKNavigationAction, decisionHandler: @escaping (WKNavigationActionPolicy) -> Void) {
        navigationDelegate?.webView?(webView, decidePolicyFor: navigationAction, decisionHandler: decisionHandler)
    }
    
    public func webView(_ webView: WKWebView,
                        decidePolicyFor navigationResponse: WKNavigationResponse,
                        decisionHandler: @escaping (WKNavigationResponsePolicy) -> Void) {
        navigationDelegate?.webView?(webView, decidePolicyFor: navigationResponse, decisionHandler: decisionHandler)
    }
    
    public func webView(_ webView: WKWebView, createWebViewWith configuration: WKWebViewConfiguration, for navigationAction: WKNavigationAction, windowFeatures: WKWindowFeatures) -> WKWebView? {
        return navigationDelegate?.webView?(webView, createWebViewWith: configuration, for: navigationAction, windowFeatures: windowFeatures)
    }
    
    public func webViewDidClose(_ webView: WKWebView) {
        self.navigationDelegate?.webViewDidClose?(webView)
    }
    
    public func webView(_ webView: WKWebView, runJavaScriptAlertPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping () -> Void) {
        navigationDelegate?.webView?(webView, runJavaScriptAlertPanelWithMessage: message, initiatedByFrame: frame, completionHandler: completionHandler)
    }
    
    public func webView(_ webView: WKWebView, runJavaScriptConfirmPanelWithMessage message: String, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (Bool) -> Void) {
        navigationDelegate?.webView?(webView, runJavaScriptConfirmPanelWithMessage: message, initiatedByFrame: frame, completionHandler: completionHandler)
    }
    
    public func webView(_ webView: WKWebView, runJavaScriptTextInputPanelWithPrompt prompt: String, defaultText: String?, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping (String?) -> Void) {
        navigationDelegate?.webView?(webView, runJavaScriptTextInputPanelWithPrompt: prompt, defaultText: defaultText, initiatedByFrame: frame, completionHandler: completionHandler)
    }
    
    @available(macOS 10.12, *)
    public func webView(_ webView: WKWebView, runOpenPanelWith parameters: WKOpenPanelParameters, initiatedByFrame frame: WKFrameInfo, completionHandler: @escaping ([URL]?) -> Void) {
        navigationDelegate?.webView?(webView, runOpenPanelWithParameters: parameters, initiatedByFrame: frame, completionHandler: completionHandler)
    }
    
    @available(macOS 12.0, *)
    public func webView(_ webView: WKWebView, decideMediaCapturePermissionsFor origin: WKSecurityOrigin, initiatedBy frame: WKFrameInfo, type: WKMediaCaptureType) async -> WKPermissionDecision {
        return (navigationDelegate?.permissionDecision?(for: type) ?? .deny)
    }
    
    public func _webView(_ webView: WKWebView, requestUserMediaAuthorizationFor devices: _WKCaptureDevices, url: URL, mainFrameURL: URL, decisionHandler: @escaping (Bool) -> Void) {
        decisionHandler(navigationDelegate?.browserMediaCaptureScreen ?? false)
    }
    
    public func _webView(_ webView: WKWebView, requestDisplayCapturePermissionFor securityOrigin: WKSecurityOrigin, initiatedByFrame frame: WKFrameInfo, withSystemAudio: Bool, decisionHandler: @escaping (WKDisplayCapturePermissionDecision) -> Void) {
        decisionHandler(.screenPrompt)
    }

    @available(macOS 12.0, *)
    public func _webView(_ webView: WKWebView, queryPermission name: String, for origin: WKSecurityOrigin) async -> WKPermissionDecision {
        return .grant
    }
}

@available(macOS 11.3, iOS 14.5, *)
extension SEBOSXWKWebViewController {
    
    public func webView(_ webView: WKWebView, navigationAction: WKNavigationAction, didBecome download: WKDownload) {
        navigationDelegate?.webView?(webView, navigationAction: navigationAction, didBecome: download)
    }
}

extension NSView {

    /// Find a subview corresponding to the className parameter, recursively.
    public func subviewWithClassName(_ className: String) -> NSView? {
        if NSStringFromClass(type(of: self)) == className {
            return self
        } else {
            let subviews = subviews
            for subview in subviews {
                return subview.subviewWithClassName(className)
            }
        }
        return nil
    }
   
}

extension WKWebView {
    
    public func contentView() -> NSView? {
        return self.subviews.first //subviewWithClassName("WKContentView")
    }
}

extension NSObject {

    enum NSObjectSwizzlingError: Error {
        case originalSelectorNotFound
    }

    @objc public func swizzleMethod(_ currentSelector: Selector, withSelector newSelector: Selector) throws {
        if let currentMethod = self.instanceMethod(for: currentSelector),
            let newMethod = self.instanceMethod(for:newSelector) {
            method_exchangeImplementations(currentMethod, newMethod)
        } else {
            throw NSObjectSwizzlingError.originalSelectorNotFound
        }
    }

    @objc public func instanceMethod(for selector: Selector) -> Method? {
        let classType: AnyClass? = object_getClass(self)
        return class_getInstanceMethod(classType, selector)
    }
}


// MARK: - Offline cover: served, not injected

/// Serves the offline lock cover from a REAL URL, so that reloading reproduces it.
///
/// THE BUG THIS EXISTS FOR. The cover used to be injected with
/// `loadHTMLString(html, baseURL: about:blank)`. An injected document has no URL that reproduces it,
/// so its committed URL is `about:blank` — and every reloader navigated there instead: ⌘R, the
/// context menu's Reload, the page's own `location.reload()`, and `reload()` called from
/// `webViewWebContentProcessDidTerminate`. The last needs NO USER ACTION: a WebKit content process
/// dies (memory pressure, GPU fault), the app helpfully reloads, and a locked child is left staring
/// at a white screen with no route back to the lock. Device-proven on 11 Sep 2026.
///
/// Three plans tried to fix this by catching the callers. Two of those reloaders never enter Swift or
/// Objective-C, so no override and no predicate can see them. Serving the cover from a URL fixes all
/// of them by construction, and fixes any future one that has no call site either.
// BEGIN blinkeredCoverHandler
final class BlinkeredOfflineCoverSchemeHandler: NSObject, WKURLSchemeHandler {

    /// CONSTRAINT A — ONLY THE CONFIGURED START URL IS EVER SERVED, anchored on the SIGNED CONFIG.
    ///
    /// THERE IS NO ARMING, AND THAT IS THE POINT. A previous version of this handler was armed by
    /// `load(_:)` with whatever URL it was asked to load. Page content can reach that call:
    /// `window.open` / `target=_blank` on a custom scheme fires `decidePolicy(newTab: true)`, and
    /// `openNewTabWithURL:` → `[newWindowWebView loadURL:url]` (`SEBOSXBrowserController.m:218`) is
    /// unguarded — so an allow-listed page could arm the handler with a URL of its own choosing and
    /// render the real lock screen as its own document. The URL filter does not stop it:
    /// `SEBURLFilter.m:376` skips the scheme check for any rule that carries no scheme, so an
    /// allow-listed HOST is allow-listed on this scheme too (driven: `blinkered-offlinecover://youtube.com`
    /// → ALLOW).
    ///
    /// THIS FILE ALREADY SAID SO. `SEBAbstractWebView.m:286` records that the start-URL anchor
    /// "replaces three earlier designs — a currentURL proxy, a one-shot latch, and an arm-on-loadURL:
    /// scheme — each of which anchored trust on an unenumerated property of some other subsystem
    /// (… nothing being able to steer a main-frame navigation) and each of which was broken by a
    /// later round." The armed version was the fourth instance of that mistake.
    ///
    /// `+[SEBAbstractWebView blinkeredIsConfiguredStart:]` (Swift: `blinkeredIsConfiguredStart(_:)` — the `…StartURL` spelling is renamed and will not compile) anchors on `org_safeexambrowser_SEB_startURL`
    /// in the signed config, which page content cannot author. No state, no latch, no arming, no
    /// call-site dependency — so Retry, the reload branch, process-termination reload and session
    /// restart all just work, with nothing to re-establish. Its comparison is gated by
    /// `tools/lockdown-tests/run-start-url-anchor-test.sh`, which slices the shipped code.

    /// CONSTRAINT B — ANSWERED SYNCHRONOUSLY, INSIDE THIS CALL.
    ///
    /// A page can abort a load (`fetch()` then abort) and WebKit then calls `stop:`. An async handler
    /// that answers afterwards raises — and `fetch()` never reaches the URL filter at all, so
    /// Constraint A does not cover it. Twelve aborted fetches crashed a naive async version. There is
    /// nothing to wait for here: the HTML is a compiled-in constant.
    func webView(_ webView: WKWebView, start urlSchemeTask: WKURLSchemeTask) {
        guard let requested = urlSchemeTask.request.url,
              SEBAbstractWebView.blinkeredIsConfiguredStart(requested) else {
            urlSchemeTask.didFailWithError(NSError(domain: NSURLErrorDomain,
                                                   code: NSURLErrorUnsupportedURL,
                                                   userInfo: [NSLocalizedDescriptionKey:
                                                              "offline cover: refused — not the configured start URL"]))
            return
        }
        let data = Data(SEBOSXWKWebViewController.blinkeredOfflineCoverHTMLBody(for: requested).utf8)
        urlSchemeTask.didReceive(URLResponse(url: requested,
                                             mimeType: "text/html",
                                             expectedContentLength: data.count,
                                             textEncodingName: "utf-8"))
        urlSchemeTask.didReceive(data)
        urlSchemeTask.didFinish()
    }

    /// Nothing is ever pending — see Constraint B — so there is nothing to cancel.
    func webView(_ webView: WKWebView, stop urlSchemeTask: WKURLSchemeTask) { }
}
// END blinkeredCoverHandler


public class SEBOSXWKWebView: WKWebView {

    weak public var sebOSXWebViewController: SEBOSXWKWebViewController?

    // Blinkered: register the FIRST click on an inactive window (e.g. clicking the top tab
    // bar of the main window while a 🪟 site window is in front) instead of just activating
    // the window and requiring a second click.
    public override func acceptsFirstMouse(for event: NSEvent?) -> Bool {
        return true
    }

    @available(macOS 10.12.2, *)
    public override func makeTouchBar() -> NSTouchBar? {
        return nil
    }
    
    public override func performKeyEquivalent(with event: NSEvent) -> Bool {
        // Cmd+R reloads the current page — the universal "something glitched, just refresh it"
        // action. Safe inside a locked session: it re-requests the same already-allowed URL in the
        // same window, so it can't be used to navigate away or escape the lockdown.
        if event.modifierFlags.contains(.command),
           event.charactersIgnoringModifiers?.lowercased() == "r" {
            self.reload()
            return true
        }
        // ⌘[ = back, ⌘] = forward — the standard Safari/Chrome shortcuts (chosen over ⌘←/⌘→ so they
        // never clash with cursor movement in a text field). goBack/goForward are no-ops with no
        // history, and history only holds already-allowed pages, so these can't escape the lockdown.
        if event.modifierFlags.contains(.command) {
            switch event.charactersIgnoringModifiers {
            case "[": self.goBack();    return true
            case "]": self.goForward(); return true
            default: break
            }
        }
        if sebOSXWebViewController?.privateClipboardEnabled == true {
            let chars = event.characters
            var status = false
            
            if event.modifierFlags.contains(.command)  {
                if chars == "c" {
                    privateCopy(self)
                    status = true
                }
                if chars == "x" {
                    privateCut(self)
                    status = true
                }
                if chars == "v" {
                    privatePaste(self)
                    status = true
                }
            }
            if status {
                return true
            }
        }
        return super.performKeyEquivalent(with: event)
    }

    @objc public func privateCopy(_ sender: Any?) {
        super.perform(NSSelectorFromString("copy:"), with: sender)
        if sebOSXWebViewController?.privateClipboardEnabled == true {
            delayWithSeconds(0.1) {
                self.sebOSXWebViewController?.storePasteboard()
            }
        }
    }

    @objc public func privateCut(_ sender: Any?) {
        super.perform(NSSelectorFromString("cut:"), with: sender)
        if sebOSXWebViewController?.privateClipboardEnabled == true {
            delayWithSeconds(0.1) {
                self.sebOSXWebViewController?.storePasteboard()
            }
        }
    }

    @objc public func privatePaste(_ sender: Any?) {
        if sebOSXWebViewController?.privateClipboardEnabled == true {
            self.sebOSXWebViewController?.restorePasteboard()
            delayWithSeconds(0.1) {
                super.perform(NSSelectorFromString("paste:"), with: sender)
                self.delayWithSeconds(0.1) {
                    NSPasteboard.general.clearContents()
                }
            }
        } else {
            super.perform(NSSelectorFromString("paste:"), with: sender)
        }
    }

    func delayWithSeconds(_ seconds: Double, completion: @escaping () -> ()) {
        DispatchQueue.main.asyncAfter(deadline: .now() + seconds) {
            completion()
        }
    }
}

#if DEBUG
// ── Offline-cover RIG CONTAINMENT HARNESS (DEBUG only — never in a release build) ────────────
// Appended to the cover HTML when the staged offline-lock.seb's startURL carries `?rigtest=1`.
// It runs INSIDE the cover's WKWebView (opaque about:blank origin, the exact context a kid would
// try to escape from) and verifies containment two ways, because a blocked navigation throws no
// JS error:
//   • CSP-caught vectors (fetch / XHR / <iframe> / form POST via form-action 'none') — a
//     `securitypolicyviolation` event fires; the harness records it and auto-marks PASS. It does
//     NOT rely on the request failing (offline would fail it anyway) — a violation event is
//     positive proof the CSP blocked it, not the network.
//   • FILTER-caught vectors (top-level `location=`, `window.open`) — no CSP directive governs
//     these; the URL filter cancels them at decidePolicyForNavigationAction, which is invisible to
//     JS. So these are operator-tapped buttons: the ONLY correct outcome is the screen STAYS on
//     this cover (and no new window opens). If tapping navigates away or opens a window →
//     CONTAINMENT FAIL, and the operator sees it directly.
// Results render to a large on-screen panel (no devtools on a locked kiosk) and also console.log a
// machine-readable line prefixed `[RIGTEST]` for Console.app correlation.
let blinkeredOfflineCoverRigTestJS = """
<style>
#rig{position:fixed;inset:0;overflow:auto;background:#0b1020;color:#dfe7f5;font:14px -apple-system,system-ui;padding:18px;z-index:2147483647}
#rig h2{margin:.2em 0 .6em;font-size:18px}#rig .row{padding:6px 8px;border-radius:6px;margin:3px 0;background:#141c30}
#rig .p{color:#7ee0a0}#rig .f{color:#ff8b8b}#rig .w{color:#ffd479}
#rig button{font:15px system-ui;margin:6px 6px 0 0;padding:10px 14px;border-radius:8px;border:0;background:#2b6cff;color:#fff}
#rig .hint{color:#9fb0c8;margin:10px 0}
</style>
<div id="rig"><h2>Blinkered offline cover — RIG CONTAINMENT TEST</h2>
<div class="hint">CSP-caught probes auto-run (all must show BLOCKED). Then TAP each navigation
button — the screen must STAY on this panel and open no new window. Any escape = FAIL.</div>
<div id="auto"></div>
<div id="viol" class="row w">CSP violations observed: 0</div>
<h2 style="font-size:15px;margin-top:14px">Navigation probes (tap — must stay here)</h2>
<button id="bLoc">Attempt location = https://example.com</button>
<button id="bForm">Attempt form POST → https://example.com</button>
<button id="bOpen">Attempt window.open(https://example.com)</button>
<div id="manual" class="hint"></div>
</div>
<script>
(function(){
  var auto=document.getElementById('auto'), violN=0, violEl=document.getElementById('viol');
  function line(name, ok, detail){var d=document.createElement('div');d.className='row '+(ok?'p':'f');
    d.textContent=(ok?'PASS  BLOCKED  ':'FAIL  REACHED   ')+name+(detail?'  — '+detail:'');auto.appendChild(d);
    console.log('[RIGTEST] '+(ok?'PASS':'FAIL')+' '+name+(detail?' '+detail:''));}
  var cspHits={};
  window.addEventListener('securitypolicyviolation',function(e){violN++;
    cspHits[(e.violatedDirective||'')+'|'+(e.blockedURI||'')]=true;
    violEl.textContent='CSP violations observed: '+violN+' (last: '+e.violatedDirective+' '+e.blockedURI+')';
    console.log('[RIGTEST] CSPVIOLATION '+e.violatedDirective+' '+e.blockedURI);});
  // Give the violation events a tick to arrive, then score each CSP-caught probe.
  var probes=[];
  // fetch to a LAN IP (proves CSP, not just offline) + a public host.
  probes.push(['fetch(http://192.168.0.1/)', function(){return fetch('http://192.168.0.1/',{mode:'no-cors'});}]);
  probes.push(['fetch(https://example.com/)', function(){return fetch('https://example.com/',{mode:'no-cors'});}]);
  probes.push(['XMLHttpRequest(https://example.com/)', function(){return new Promise(function(res,rej){
    try{var x=new XMLHttpRequest();x.open('GET','https://example.com/');x.onerror=function(){rej(0)};x.onload=function(){res(0)};x.send();}catch(e){rej(e)}});}]);
  probes.push(['<iframe src=https://example.com>', function(){return new Promise(function(res){
    // Resolve with the iframe element so scoring can inspect where it actually ended up.
    var f=document.createElement('iframe');f.src='https://example.com/';
    f.onload=function(){res(f)};document.body.appendChild(f);setTimeout(function(){res(f)},1500);});}]);
  // Each: BLOCKED (PASS) if it throws/rejects OR a CSP violation was recorded for it.
  Promise.allSettled(probes.map(function(p){return p[1]();})).then(function(results){
    setTimeout(function(){
      var names=['connect-src (fetch LAN)','connect-src (fetch public)','connect-src (XHR)','frame-src (iframe)'];
      results.forEach(function(r,i){
        var blockedByThrow = (r.status==='rejected');
        var blockedByCsp = violN>0; // any connect/frame violation fired
        if(i===3){
          // A CSP-blocked (or offline) iframe still fires onload for its blank fallback, so onload
          // alone is NOT reachability. It REACHED example.com only if its document is cross-origin
          // (accessing contentWindow.location throws) or its location is actually example.com. A
          // blocked iframe sits at same-origin about:blank — readable, not example.com → BLOCKED.
          var f=r.value, reached=false, note='blank';
          try { var href=(f&&f.contentWindow)?f.contentWindow.location.href:''; reached=href.indexOf('example.com')>=0; note=href||'no-frame'; }
          catch(e){ reached=true; note='cross-origin (loaded)'; }
          line(names[i], !reached, note);
        } else {
          line(names[i], blockedByThrow||blockedByCsp, blockedByThrow?'request errored':'');
        }
      });
      // form-action 'none' is CSP-caught but only fires on submit → tested via the button below too.
      line('CSP present (violations fired)', violN>0, violN+' violation(s)');
    },300);
  });
  // Manual navigation probes — the ONLY correct result is "you still see this panel".
  var manual=document.getElementById('manual');
  function mark(t){manual.innerHTML='Fired: '+t+' — if you can still read this after 3s and no new '+
    'window opened, that vector is CONTAINED (PASS). If the screen changed or a window opened, FAIL.';}
  document.getElementById('bLoc').onclick=function(){mark('location=');console.log('[RIGTEST] FIRE location');location.href='https://example.com/';};
  document.getElementById('bForm').onclick=function(){mark('form POST');console.log('[RIGTEST] FIRE formPOST');
    var f=document.createElement('form');f.method='POST';f.action='https://example.com/';document.body.appendChild(f);f.submit();};
  document.getElementById('bOpen').onclick=function(){mark('window.open');console.log('[RIGTEST] FIRE window.open');
    var w=window.open('https://example.com/','_blank');console.log('[RIGTEST] window.open returned '+(w?'a window ref':'null'));};
})();
</script>
"""
#endif
