/* ============================================================
* QupZilla - WebKit based browser
* Copyright (C) 2010-2014  David Rosca <nowrep@gmail.com>
*
* This program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation, either version 3 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
* ============================================================ */

#include "webview.h"
#include "webpage.h"
#include "mainapplication.h"
#include "qztools.h"
#include "iconprovider.h"
#include "history.h"
#include "pluginproxy.h"
#include "downloadmanager.h"
#include "sourceviewer.h"
#include "siteinfo.h"
#include "searchenginesmanager.h"
#include "browsinglibrary.h"
#include "bookmarksmanager.h"
#include "settings.h"
#include "qzsettings.h"
#include "enhancedmenu.h"

#ifdef USE_HUNSPELL
#include "qtwebkit/spellcheck/speller.h"
#endif

#ifdef Q_OS_MAC
#include "macwebviewscroller.h"
#endif

#include <QDir>
#include <QTimer>
#include <QDesktopServices>
#include <QNetworkRequest>
#include <QWebEngineHistory>
#include <QClipboard>
#include <QTouchEvent>
#include <QPrintPreviewDialog>

WebView::WebView(QWidget* parent)
    : QWebEngineView(parent)
    , m_currentZoom(100)
    , m_isLoading(false)
    , m_progress(0)
    , m_clickedFrame(0)
    , m_page(0)
    , m_actionReload(0)
    , m_actionStop(0)
    , m_actionsInitialized(false)
    , m_disableTouchMocking(false)
    , m_isReloading(false)
    , m_hasRss(false)
    , m_rssChecked(false)
{
    connect(this, SIGNAL(loadStarted()), this, SLOT(slotLoadStarted()));
    connect(this, SIGNAL(loadProgress(int)), this, SLOT(slotLoadProgress(int)));
    connect(this, SIGNAL(loadFinished(bool)), this, SLOT(slotLoadFinished()));
    connect(this, SIGNAL(urlChanged(QUrl)), this, SLOT(slotUrlChanged(QUrl)));

    // Zoom levels same as in firefox
    m_zoomLevels << 30 << 50 << 67 << 80 << 90 << 100 << 110 << 120 << 133 << 150 << 170 << 200 << 240 << 300;

#if QTWEBKIT_TO_2_3
    installEventFilter(this);
#endif

#ifdef Q_OS_MAC
    new MacWebViewScroller(this);
#endif
}

QIcon WebView::icon() const
{
    if (url().scheme() == QLatin1String("qupzilla")) {
        return QIcon(":icons/qupzilla.png");
    }

    if (url().scheme() == QLatin1String("file")) {
        return qIconProvider->standardIcon(QStyle::SP_DriveHDIcon);
    }

    if (url().scheme() == QLatin1String("ftp")) {
        return qIconProvider->standardIcon(QStyle::SP_ComputerIcon);
    }

    // FIXME
    // if (!QWebEngineView::icon().isNull()) {
    //     return QWebEngineView::icon();
    // }

    if (!m_siteIcon.isNull() && m_siteIconUrl.host() == url().host()) {
        return m_siteIcon;
    }

    return _iconForUrl(url());
}

QString WebView::title() const
{
    QString title = QWebEngineView::title();

    if (title.isEmpty()) {
        title = url().toString(QUrl::RemoveFragment);
    }

    if (title.isEmpty() || title == QLatin1String("about:blank")) {
        return tr("No Named Page");
    }

    return title;
}

QUrl WebView::url() const
{
    QUrl returnUrl = page()->url();

    if (returnUrl.isEmpty()) {
        returnUrl = m_aboutToLoadUrl;
    }

    if (returnUrl.toString() == QLatin1String("about:blank")) {
        returnUrl = QUrl();
    }

    return returnUrl;
}

WebPage* WebView::page() const
{
    return m_page;
}

void WebView::setPage(QWebEnginePage* page)
{
    if (m_page == page) {
        return;
    }

    QWebEngineView::setPage(page);
    m_page = qobject_cast<WebPage*>(page);

    setZoom(qzSettings->defaultZoom);
    connect(m_page, SIGNAL(privacyChanged(bool)), this, SIGNAL(privacyChanged(bool)));

}

void WebView::load(const QUrl &url)
{
    load(QNetworkRequest(url));
}

void WebView::load(const QNetworkRequest &request, QNetworkAccessManager::Operation operation, const QByteArray &body)
{
    const QUrl reqUrl = request.url();

    if (reqUrl.scheme() == QLatin1String("javascript")) {
        // Getting scriptSource from PercentEncoding to properly load bookmarklets
        // First check if url is percent encoded (let's just look for space)
        QString scriptSource;
        if (reqUrl.path().trimmed().contains(' ')) {
            scriptSource = reqUrl.toString().mid(11);
        }
        else {
            scriptSource = QUrl::fromPercentEncoding(reqUrl.toString().mid(11).toUtf8());
        }
        page()->runJavaScript(scriptSource);
        return;
    }

    if (reqUrl.isEmpty() || isUrlValid(reqUrl)) {
        QWebEngineView::load(request.url());
        m_aboutToLoadUrl = reqUrl;
        return;
    }

    SearchEnginesManager::SearchResult res = mApp->searchEnginesManager()->searchResult(reqUrl.toString());
    const QUrl searchUrl = res.request.url();

    QWebEngineView::load(res.request.url());
    m_aboutToLoadUrl = searchUrl;
}

bool WebView::loadingError() const
{
    return page()->loadingError();
}

bool WebView::isLoading() const
{
    return m_isLoading;
}

int WebView::loadingProgress() const
{
    return m_progress;
}

void WebView::fakeLoadingProgress(int progress)
{
    emit loadStarted();
    emit loadProgress(progress);
}

bool WebView::hasRss() const
{
    return m_hasRss;
}

bool WebView::isUrlValid(const QUrl &url)
{
    // Valid url must have scheme and actually contains something (therefore scheme:// is invalid)
    return url.isValid() && !url.scheme().isEmpty() && (!url.host().isEmpty() || !url.path().isEmpty() || url.hasQuery());
}

QUrl WebView::guessUrlFromString(const QString &string)
{
    QString trimmedString = string.trimmed();

    // Check the most common case of a valid url with scheme and host first
    QUrl url = QUrl::fromEncoded(trimmedString.toUtf8(), QUrl::TolerantMode);
    if (url.isValid() && !url.scheme().isEmpty() && !url.host().isEmpty()) {
        return url;
    }

    // Absolute files that exists
    if (QDir::isAbsolutePath(trimmedString) && QFile::exists(trimmedString)) {
        return QUrl::fromLocalFile(trimmedString);
    }

    // If the string is missing the scheme or the scheme is not valid prepend a scheme
    QString scheme = url.scheme();
    if (scheme.isEmpty() || scheme.contains(QLatin1Char('.')) || scheme == QLatin1String("localhost")) {
        // Do not do anything for strings such as "foo", only "foo.com"
        int dotIndex = trimmedString.indexOf(QLatin1Char('.'));
        if (dotIndex != -1 || trimmedString.startsWith(QLatin1String("localhost"))) {
            const QString hostscheme = trimmedString.left(dotIndex).toLower();
            QByteArray scheme = (hostscheme == QLatin1String("ftp")) ? "ftp" : "http";
            trimmedString = QLatin1String(scheme) + QLatin1String("://") + trimmedString;
        }
        url = QUrl::fromEncoded(trimmedString.toUtf8(), QUrl::TolerantMode);
    }

    if (url.isValid()) {
        return url;
    }

    return QUrl();
}

void WebView::addNotification(QWidget* notif)
{
    emit showNotification(notif);
}

void WebView::applyZoom()
{
    setZoomFactor(qreal(m_currentZoom) / 100.0);
}

void WebView::zoomIn()
{
    int i = m_zoomLevels.indexOf(m_currentZoom);

    if (i < m_zoomLevels.count() - 1) {
        m_currentZoom = m_zoomLevels[i + 1];
    }

    applyZoom();
}

void WebView::zoomOut()
{
    int i = m_zoomLevels.indexOf(m_currentZoom);

    if (i > 0) {
        m_currentZoom = m_zoomLevels[i - 1];
    }

    applyZoom();
}

void WebView::zoomReset()
{
    m_currentZoom = 100;
    applyZoom();
}

void WebView::reload()
{
    m_isReloading = true;
    if (QWebEngineView::url().isEmpty() && !m_aboutToLoadUrl.isEmpty()) {
        load(m_aboutToLoadUrl);
        return;
    }

    QWebEngineView::reload();
}

void WebView::back()
{
    QWebEngineHistory* history = page()->history();

    if (history->canGoBack()) {
        history->back();

        emit urlChanged(url());
    }
}

void WebView::forward()
{
    QWebEngineHistory* history = page()->history();

    if (history->canGoForward()) {
        history->forward();

        emit urlChanged(url());
    }
}

void WebView::editDelete()
{
    QKeyEvent ev(QEvent::KeyPress, Qt::Key_Delete, Qt::NoModifier);
    QApplication::sendEvent(this, &ev);
}

void WebView::selectAll()
{
    triggerPageAction(QWebEnginePage::SelectAll);
}

void WebView::slotLoadStarted()
{
    m_isLoading = true;
    m_progress = 0;

    if (m_actionsInitialized) {
        m_actionStop->setEnabled(true);
        m_actionReload->setEnabled(false);
    }

    m_rssChecked = false;
    emit rssChanged(false);
}

void WebView::slotLoadProgress(int progress)
{
    m_progress = progress;

    if (m_progress > 60) {
        checkRss();
    }
}

void WebView::slotLoadFinished()
{
    m_isLoading = false;
    m_progress = 100;

    if (m_actionsInitialized) {
        m_actionStop->setEnabled(false);
        m_actionReload->setEnabled(true);
    }

    if (!m_isReloading) {
        mApp->history()->addHistoryEntry(this);
    }

    m_isReloading = false;
    m_lastUrl = url();
}

void WebView::frameStateChanged()
{
    // QWebEngineFrame::baseUrl() is not updated yet, so we are invoking 0 second timer
    QTimer::singleShot(0, this, SLOT(emitChangedUrl()));
}

void WebView::emitChangedUrl()
{
    emit urlChanged(url());
}

void WebView::checkRss()
{
}

void WebView::slotUrlChanged(const QUrl &url)
{
    static QStringList exceptions;
    if (exceptions.isEmpty()) {
        exceptions << "google." << "twitter.";
    }

    // Disable touch mocking on pages known not to work properly
    const QString host = url.host();
    m_disableTouchMocking = false;

    foreach (const QString &site, exceptions) {
        if (host.contains(site)) {
            m_disableTouchMocking = true;
        }
    }
}

void WebView::openUrlInNewWindow()
{
    if (QAction* action = qobject_cast<QAction*>(sender())) {
        mApp->makeNewWindow(Qz::BW_NewWindow, action->data().toUrl());
    }
}

void WebView::sendLinkByMail()
{
    if (QAction* action = qobject_cast<QAction*>(sender())) {
        const QUrl mailUrl = QUrl::fromEncoded("mailto:%20?body=" + QUrl::toPercentEncoding(action->data().toUrl().toEncoded()));
        QDesktopServices::openUrl(mailUrl);
    }
}

void WebView::sendPageByMail()
{
    const QUrl mailUrl = QUrl::fromEncoded("mailto:%20?body=" + QUrl::toPercentEncoding(url().toEncoded()) + "&subject=" + QUrl::toPercentEncoding(title()));
    QDesktopServices::openUrl(mailUrl);
}

void WebView::copyLinkToClipboard()
{
    if (QAction* action = qobject_cast<QAction*>(sender())) {
        QApplication::clipboard()->setText(action->data().toUrl().toEncoded());
    }
}

void WebView::savePageAs()
{
    if (url().isEmpty() || url().toString() == QLatin1String("about:blank")) {
        return;
    }

    QNetworkRequest request(url());
    QString suggestedFileName = QzTools::getFileNameFromUrl(url());
    if (!suggestedFileName.contains(QLatin1Char('.'))) {
        suggestedFileName.append(QLatin1String(".html"));
    }

    DownloadManager::DownloadInfo info;
    info.page = page();
    info.suggestedFileName = suggestedFileName;
    info.askWhatToDo = false;
    info.forceChoosingPath = true;

    DownloadManager* dManager = mApp->downManager();
    dManager->download(request, info);
}

void WebView::openUrlInNewTab(const QUrl &url, Qz::NewTabPositionFlags position)
{
    loadInNewTab(QNetworkRequest(url), QNetworkAccessManager::GetOperation, QByteArray(), position);
}

void WebView::downloadUrlToDisk()
{
    if (QAction* action = qobject_cast<QAction*>(sender())) {
        QNetworkRequest request(action->data().toUrl());

        DownloadManager::DownloadInfo info;
        info.page = page();
        info.suggestedFileName = QString();
        info.askWhatToDo = false;
        info.forceChoosingPath = true;

        DownloadManager* dManager = mApp->downManager();
        dManager->download(request, info);
    }
}

void WebView::openActionUrl()
{
    if (QAction* action = qobject_cast<QAction*>(sender())) {
        load(action->data().toUrl());
    }
}

void WebView::showSource(QWebEngineFrame* frame, const QString &selectedHtml)
{
}

void WebView::showSiteInfo()
{
}

void WebView::searchSelectedText()
{
    SearchEngine engine = mApp->searchEnginesManager()->activeEngine();
    if (QAction* act = qobject_cast<QAction*>(sender())) {
        if (act->data().isValid()) {
            engine = act->data().value<SearchEngine>();
        }
    }

    SearchEnginesManager::SearchResult res = mApp->searchEnginesManager()->searchResult(engine, selectedText());
    loadInNewTab(res.request, res.operation, res.data, Qz::NT_SelectedTab);
}

void WebView::searchSelectedTextInBackgroundTab()
{
    SearchEngine engine = mApp->searchEnginesManager()->activeEngine();
    if (QAction* act = qobject_cast<QAction*>(sender())) {
        if (act->data().isValid()) {
            engine = act->data().value<SearchEngine>();
        }
    }

    SearchEnginesManager::SearchResult res = mApp->searchEnginesManager()->searchResult(engine, selectedText());
    loadInNewTab(res.request, res.operation, res.data, Qz::NT_NotSelectedTab);
}

void WebView::bookmarkLink()
{
    if (QAction* action = qobject_cast<QAction*>(sender())) {
        if (action->data().isNull()) {
            mApp->browsingLibrary()->bookmarksManager()->addBookmark(this);
        }
        else {
            const QVariantList bData = action->data().value<QVariantList>();
            const QString bookmarkTitle = bData.at(1).toString().isEmpty() ? title() : bData.at(1).toString();

            mApp->browsingLibrary()->bookmarksManager()->insertBookmark(bData.at(0).toUrl(), bookmarkTitle, icon());
        }
    }
}

void WebView::showSourceOfSelection()
{
}

void WebView::openUrlInSelectedTab()
{
    if (QAction* action = qobject_cast<QAction*>(sender())) {
        openUrlInNewTab(action->data().toUrl(), Qz::NT_CleanSelectedTab);
    }
}

void WebView::openUrlInBackgroundTab()
{
    if (QAction* action = qobject_cast<QAction*>(sender())) {
        openUrlInNewTab(action->data().toUrl(), Qz::NT_CleanNotSelectedTab);
    }
}

void WebView::userDefinedOpenUrlInNewTab(const QUrl &url, bool invert)
{
    Qz::NewTabPositionFlags position = qzSettings->newTabPosition;
    if (invert) {
        if (position & Qz::NT_SelectedTab) {
            position &= ~Qz::NT_SelectedTab;
            position |= Qz::NT_NotSelectedTab;
        }
        else {
            position &= ~Qz::NT_NotSelectedTab;
            position |= Qz::NT_SelectedTab;

        }
    }

    QUrl actionUrl;

    if (!url.isEmpty()) {
        actionUrl = url;
    }
    else if (QAction* action = qobject_cast<QAction*>(sender())) {
        actionUrl = action->data().toUrl();
    }

    openUrlInNewTab(actionUrl, position);
}

void WebView::userDefinedOpenUrlInBgTab(const QUrl &url)
{
    QUrl actionUrl;

    if (!url.isEmpty()) {
        actionUrl = url;
    }
    else if (QAction* action = qobject_cast<QAction*>(sender())) {
        actionUrl = action->data().toUrl();
    }

    userDefinedOpenUrlInNewTab(actionUrl, true);
}

void WebView::loadClickedFrame()
{
}

void WebView::loadClickedFrameInNewTab(bool invert)
{
}

void WebView::loadClickedFrameInBgTab()
{
}

void WebView::reloadClickedFrame()
{
}

void WebView::printClickedFrame()
{
}

void WebView::clickedFrameZoomIn()
{
    qreal zFactor = page()->zoomFactor() + 0.1;
    if (zFactor > 2.5) {
        zFactor = 2.5;
    }

    page()->setZoomFactor(zFactor);
}

void WebView::clickedFrameZoomOut()
{
    qreal zFactor = page()->zoomFactor() - 0.1;
    if (zFactor < 0.5) {
        zFactor = 0.5;
    }

    page()->setZoomFactor(zFactor);
}

void WebView::clickedFrameZoomReset()
{
    page()->setZoomFactor(zoomFactor());
}

void WebView::showClickedFrameSource()
{
}

void WebView::printPage(QWebEngineFrame* frame)
{
}

QUrl WebView::lastUrl()
{
    return m_lastUrl;
}

void WebView::createSearchEngine()
{
}

void WebView::pauseMedia()
{
}

void WebView::muteMedia()
{
}

void WebView::addSpeedDial()
{
}

void WebView::configureSpeedDial()
{
}

void WebView::wheelEvent(QWheelEvent* event)
{
    if (event->modifiers() & Qt::ControlModifier) {
        event->delta() > 0 ? zoomIn() : zoomOut();
        event->accept();

        return;
    }

    QWebEngineView::wheelEvent(event);
}

void WebView::mousePressEvent(QMouseEvent* event)
{
    switch (event->button()) {
    case Qt::XButton1:
        back();
        event->accept();
        break;

    case Qt::XButton2:
        forward();
        event->accept();
        break;

    case Qt::MiddleButton: {
        // QWebEngineFrame* frame = page()->frameAt(event->pos());
        // if (frame) {
        //     m_clickedUrl = frame->hitTestContent(event->pos()).linkUrl();
        //     if (!m_clickedUrl.isEmpty()) {
        //         return;
        //     }
        // }

        break;
    }

    case Qt::LeftButton: {
    }

    default:
        break;
    }

    QWebEngineView::mousePressEvent(event);
}

void WebView::mouseReleaseEvent(QMouseEvent* event)
{
    switch (event->button()) {
    case Qt::MiddleButton: {

        break;
    }

    default:
        break;
    }

    QWebEngineView::mouseReleaseEvent(event);
}

void WebView::mouseMoveEvent(QMouseEvent* event)
{
    QWebEngineView::mouseMoveEvent(event);
}

void WebView::keyPressEvent(QKeyEvent* event)
{
    int eventKey = event->key();

    // The right/left arrow keys within contents with right to left (RTL) layout have
    // reversed behavior than left to right (LTR) layout.
    // Example: Key_Right within LTR layout triggers QWebEnginePage::MoveToNextChar but,
    // Key_Right within RTL layout should trigger QWebEnginePage::MoveToPreviousChar

    switch (eventKey) {
    case Qt::Key_C:
        if (event->modifiers() == Qt::ControlModifier) {
            triggerPageAction(QWebEnginePage::Copy);
            event->accept();
            return;
        }
        break;

    case Qt::Key_A:
        if (event->modifiers() == Qt::ControlModifier) {
            selectAll();
            event->accept();
            return;
        }
        break;

    case Qt::Key_Insert:
        if (event->modifiers() == Qt::ControlModifier) {
            triggerPageAction(QWebEnginePage::Copy);
            event->accept();
            return;
        }
        if (event->modifiers() == Qt::ShiftModifier) {
            triggerPageAction(QWebEnginePage::Paste);
            event->accept();
            return;
        }
        break;

    default:
        break;
    }

    QWebEngineView::keyPressEvent(event);
}

void WebView::keyReleaseEvent(QKeyEvent* event)
{
    QWebEngineView::keyReleaseEvent(event);
}

void WebView::resizeEvent(QResizeEvent* event)
{
    QWebEngineView::resizeEvent(event);
    emit viewportResized(size());
}

void WebView::setZoom(int zoom)
{
    m_currentZoom = zoom;
    applyZoom();
}

///
// This function was taken and modified from QTestBrowser to fix bug #33 with flightradar24.com
// You can find original source and copyright here:
// http://gitorious.org/+qtwebkit-developers/webkit/qtwebkit/blobs/qtwebkit-2.2/Tools/QtTestBrowser/launcherwindow.cpp
///
bool WebView::eventFilter(QObject* obj, QEvent* event)
{
// This hack is no longer needed with QtWebKit 2.3 (bundled in Qt 5)
#if QTWEBKIT_TO_2_3
    if (obj != this || m_disableTouchMocking) {
        return false;
    }

    if (event->type() == QEvent::MouseButtonPress ||
            event->type() == QEvent::MouseButtonRelease ||
            event->type() == QEvent::MouseButtonDblClick ||
            event->type() == QEvent::MouseMove) {

        QMouseEvent* ev = static_cast<QMouseEvent*>(event);

        if (ev->type() == QEvent::MouseMove && !(ev->buttons() & Qt::LeftButton)) {
            return false;
        }

        if (ev->type() == QEvent::MouseButtonPress && !(ev->buttons() & Qt::LeftButton)) {
            return false;
        }

        QEvent::Type type = QEvent::TouchUpdate;
        QTouchEvent::TouchPoint touchPoint;
        touchPoint.setId(0);
        touchPoint.setScreenPos(ev->globalPos());
        touchPoint.setPos(ev->pos());
        touchPoint.setPressure(1);

        switch (ev->type()) {
        case QEvent::MouseButtonPress:
        case QEvent::MouseButtonDblClick:
            touchPoint.setState(Qt::TouchPointPressed);
            type = QEvent::TouchBegin;

            break;

        case QEvent::MouseButtonRelease:
            touchPoint.setState(Qt::TouchPointReleased);
            type = QEvent::TouchEnd;

            break;

        case QEvent::MouseMove:
            touchPoint.setState(Qt::TouchPointMoved);
            type = QEvent::TouchUpdate;

            break;

        default:
            break;
        }

        QList<QTouchEvent::TouchPoint> touchPoints;
        touchPoints << touchPoint;

        QTouchEvent touchEv(type);
        touchEv.setTouchPoints(touchPoints);
        QCoreApplication::sendEvent(page(), &touchEv);

        return false;
    }
#endif
    return QWebEngineView::eventFilter(obj, event);
}

void WebView::disconnectObjects()
{
    disconnect(this);
}
