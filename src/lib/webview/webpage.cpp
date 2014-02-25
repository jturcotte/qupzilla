/* ============================================================
* QupZilla - WebKit based browser
* Copyright (C) 2010-2013  David Rosca <nowrep@gmail.com>
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
#include "webpage.h"
#include "tabbedwebview.h"
#include "tabwidget.h"
#include "qupzilla.h"
#include "pluginproxy.h"
#include "downloadmanager.h"
#include "webpluginfactory.h"
#include "mainapplication.h"
#include "checkboxdialog.h"
#include "widget.h"
#include "qztools.h"
#include "speeddial.h"
#include "autofill.h"
#include "popupwebpage.h"
#include "popupwebview.h"
#include "networkmanagerproxy.h"
#include "adblockicon.h"
#include "adblockmanager.h"
#include "iconprovider.h"
#include "qzsettings.h"
#include "useragentmanager.h"
#include "delayedfilewatcher.h"
#include "recoverywidget.h"
#include "html5permissions/html5permissionsmanager.h"
#include "schemehandlers/fileschemehandler.h"

#ifdef NONBLOCK_JS_DIALOGS
#include "ui_jsconfirm.h"
#include "ui_jsalert.h"
#include "ui_jsprompt.h"

#include <QPushButton>
#endif

#include <QAuthenticator>
#include <QDir>
#include <QFormLayout>
#include <QLabel>
#include <QLineEdit>
#include <QMouseEvent>
#include <QWebEngineHistory>
#include <QTimer>
#include <QNetworkReply>
#include <QDebug>
#include <QDesktopServices>
#include <QMessageBox>
#include <QFileDialog>
#include <QWebEngineSecurityOrigin>

QString WebPage::s_lastUploadLocation = QDir::homePath();
QUrl WebPage::s_lastUnsupportedUrl;
QTime WebPage::s_lastUnsupportedUrlTime;
QList<WebPage*> WebPage::s_livingPages;

WebPage::WebPage(QObject* parent)
    : QWebEnginePage(parent)
    , m_view(0)
    , m_fileWatcher(0)
    , m_runningLoop(0)
    , m_loadProgress(-1)
    , m_blockAlerts(false)
    , m_secureStatus(false)
    , m_adjustingScheduled(false)
{
    history()->setMaximumItemCount(20);

    connect(this, SIGNAL(loadProgress(int)), this, SLOT(progress(int)));
    connect(this, SIGNAL(loadFinished(bool)), this, SLOT(finished()));
    connect(this, SIGNAL(printRequested(QWebEngineFrame*)), this, SLOT(printFrame(QWebEngineFrame*)));
    connect(this, SIGNAL(downloadRequested(QNetworkRequest)), this, SLOT(downloadRequested(QNetworkRequest)));
    connect(this, SIGNAL(windowCloseRequested()), this, SLOT(windowCloseRequested()));
    connect(this, SIGNAL(authenticationRequired(const QUrl&, QAuthenticator*)), this, SLOT(authentication(const QUrl&, QAuthenticator*)));
    connect(this, SIGNAL(proxyAuthenticationRequired(const QUrl&, QAuthenticator*, const QString&)), this, SLOT(proxyAuthentication(const QUrl&, QAuthenticator*, const QString&)));

#if QTWEBKIT_FROM_2_2
    connect(this, SIGNAL(featurePermissionRequested(QWebEngineFrame*,QWebEnginePage::Feature)),
            this, SLOT(featurePermissionRequested(QWebEngineFrame*,QWebEnginePage::Feature)));
#endif

#if QTWEBKIT_FROM_2_3
    connect(this, SIGNAL(applicationCacheQuotaExceeded(QWebEngineSecurityOrigin*,quint64,quint64)),
            this, SLOT(appCacheQuotaExceeded(QWebEngineSecurityOrigin*,quint64)));
#elif QTWEBKIT_FROM_2_2
    connect(this, SIGNAL(applicationCacheQuotaExceeded(QWebEngineSecurityOrigin*,quint64)),
            this, SLOT(appCacheQuotaExceeded(QWebEngineSecurityOrigin*,quint64)));
#endif

    s_livingPages.append(this);
}

void WebPage::setWebView(TabbedWebView* view)
{
    if (m_view == view) {
        return;
    }

    if (m_view) {
        delete m_view;
        m_view = 0;
    }

    m_view = view;
    m_view->setWebPage(this);

    connect(m_view, SIGNAL(urlChanged(QUrl)), this, SLOT(urlChanged(QUrl)));
}

void WebPage::scheduleAdjustPage()
{
    WebView* webView = qobject_cast<WebView*>(view());
    if (!webView) {
        return;
    }

    if (webView->isLoading()) {
        m_adjustingScheduled = true;
    }
    else {
        const QSize originalSize = webView->size();
        QSize newSize(originalSize.width() - 1, originalSize.height() - 1);

        webView->resize(newSize);
        webView->resize(originalSize);
    }
}

bool WebPage::loadingError() const
{
    return false;
}

void WebPage::addRejectedCerts(const QList<QSslCertificate> &certs)
{
    foreach (const QSslCertificate &cert, certs) {
        if (!m_rejectedSslCerts.contains(cert)) {
            m_rejectedSslCerts.append(cert);
        }
    }
}

bool WebPage::containsRejectedCerts(const QList<QSslCertificate> &certs)
{
    int matches = 0;

    foreach (const QSslCertificate &cert, certs) {
        if (m_rejectedSslCerts.contains(cert)) {
            ++matches;
        }

        if (m_sslCert == cert) {
            m_sslCert.clear();
        }
    }

    return matches == certs.count();
}

bool WebPage::isRunningLoop()
{
    return m_runningLoop;
}

bool WebPage::isLoading() const
{
    return m_loadProgress < 100;
}

void WebPage::urlChanged(const QUrl &url)
{
    if (isLoading()) {
        m_blockAlerts = false;
    }
}

void WebPage::progress(int prog)
{
    m_loadProgress = prog;

    bool secStatus = QzTools::isCertificateValid(sslCertificate());

    if (secStatus != m_secureStatus) {
        m_secureStatus = secStatus;
        emit privacyChanged(QzTools::isCertificateValid(sslCertificate()));
    }
}

void WebPage::finished()
{
    progress(100);

    if (m_adjustingScheduled) {
        m_adjustingScheduled = false;
        setZoomFactor(zoomFactor() + 1);
        setZoomFactor(zoomFactor() - 1);
    }

    // File scheme watcher
    if (url().scheme() == QLatin1String("file")) {
        QFileInfo info(url().toLocalFile());
        if (info.isFile()) {
            if (!m_fileWatcher) {
                m_fileWatcher = new DelayedFileWatcher(this);
                connect(m_fileWatcher, SIGNAL(delayedFileChanged(QString)), this, SLOT(watchedFileChanged(QString)));
            }

            const QString filePath = url().toLocalFile();

            if (QFile::exists(filePath) && !m_fileWatcher->files().contains(filePath)) {
                m_fileWatcher->addPath(filePath);
            }
        }
    }
    else if (m_fileWatcher && !m_fileWatcher->files().isEmpty()) {
        m_fileWatcher->removePaths(m_fileWatcher->files());
    }

    // AdBlock
    cleanBlockedObjects();
}

void WebPage::watchedFileChanged(const QString &file)
{
    if (url().toLocalFile() == file) {
        triggerAction(QWebEnginePage::Reload);
    }
}

void WebPage::printFrame(QWebEngineFrame* frame)
{
    WebView* webView = qobject_cast<WebView*>(view());
    if (!webView) {
        return;
    }

    webView->printPage(frame);
}

void WebPage::addJavaScriptObject()
{
}

void WebPage::handleUnsupportedContent(QNetworkReply* reply)
{
}

void WebPage::handleUnknownProtocol(const QUrl &url)
{
    const QString protocol = url.scheme();

    if (protocol == QLatin1String("mailto")) {
        desktopServicesOpen(url);
        return;
    }

    if (qzSettings->blockedProtocols.contains(protocol)) {
        qDebug() << "WebPage::handleUnknownProtocol Protocol" << protocol << "is blocked!";
        return;
    }

    if (qzSettings->autoOpenProtocols.contains(protocol)) {
        desktopServicesOpen(url);
        return;
    }

    CheckBoxDialog dialog(QDialogButtonBox::Yes | QDialogButtonBox::No, view());

    const QString wrappedUrl = QzTools::alignTextToWidth(url.toString(), "<br/>", dialog.fontMetrics(), 450);
    const QString text = tr("QupZilla cannot handle <b>%1:</b> links. The requested link "
                            "is <ul><li>%2</li></ul>Do you want QupZilla to try "
                            "open this link in system application?").arg(protocol, wrappedUrl);

    dialog.setText(text);
    dialog.setCheckBoxText(tr("Remember my choice for this protocol"));
    dialog.setWindowTitle(tr("External Protocol Request"));
    dialog.setIcon(qIconProvider->standardIcon(QStyle::SP_MessageBoxQuestion));

    switch (dialog.exec()) {
    case QDialog::Accepted:
        if (dialog.isChecked()) {
            qzSettings->autoOpenProtocols.append(protocol);
            qzSettings->saveSettings();
        }

        QDesktopServices::openUrl(url);
        break;

    case QDialog::Rejected:
        if (dialog.isChecked()) {
            qzSettings->blockedProtocols.append(protocol);
            qzSettings->saveSettings();
        }

        break;

    default:
        break;
    }
}

void WebPage::desktopServicesOpen(const QUrl &url)
{
    // Open same url only once in 2 secs

    if (s_lastUnsupportedUrl != url || QTime::currentTime() > s_lastUnsupportedUrlTime.addSecs(2)) {
        s_lastUnsupportedUrl = url;
        s_lastUnsupportedUrlTime = QTime::currentTime();
        QDesktopServices::openUrl(url);
    }
    else {
        qWarning() << "WebPage::desktopServicesOpen Url" << url << "has already been opened!\n"
                   "Ignoring it to prevent infinite loop!";
    }
}

void WebPage::downloadRequested(const QNetworkRequest &request)
{
    DownloadManager* dManager = mApp->downManager();
    dManager->download(request, this);
}

void WebPage::windowCloseRequested()
{
    WebView* webView = qobject_cast<WebView*>(view());
    if (!webView) {
        return;
    }

    webView->closeView();
}

void WebPage::authentication(const QUrl &requestUrl, QAuthenticator *auth)
{
    QDialog* dialog = new QDialog();
    dialog->setWindowTitle(tr("Authorisation required"));

    QFormLayout* formLa = new QFormLayout(dialog);

    QLabel* label = new QLabel(dialog);
    QLabel* userLab = new QLabel(dialog);
    QLabel* passLab = new QLabel(dialog);
    userLab->setText(tr("Username: "));
    passLab->setText(tr("Password: "));

    QLineEdit* user = new QLineEdit(dialog);
    QLineEdit* pass = new QLineEdit(dialog);
    pass->setEchoMode(QLineEdit::Password);

    QDialogButtonBox* box = new QDialogButtonBox(dialog);
    box->addButton(QDialogButtonBox::Ok);
    box->addButton(QDialogButtonBox::Cancel);
    connect(box, SIGNAL(rejected()), dialog, SLOT(reject()));
    connect(box, SIGNAL(accepted()), dialog, SLOT(accept()));

    label->setText(tr("A username and password are being requested by %1. "
                      "The site says: \"%2\"").arg(requestUrl.host(), QzTools::escape(auth->realm())));
    formLa->addRow(label);

    formLa->addRow(userLab, user);
    formLa->addRow(passLab, pass);

    formLa->addWidget(box);
    bool shouldUpdateEntry = false;

    // Try to set the originating WebTab as a current tab
    TabbedWebView* view = qobject_cast<TabbedWebView*>(this->view());
    if (view) {
        view->setAsCurrentTab();
    }

    if (dialog->exec() != QDialog::Accepted) {
        return;
    }

    auth->setUser(user->text());
    auth->setPassword(pass->text());
}

void WebPage::proxyAuthentication(const QUrl &requestUrl, QAuthenticator *auth, const QString &proxyHost)
{
    QDialog* dialog = new QDialog();
    dialog->setWindowTitle(tr("Proxy authorisation required"));

    QFormLayout* formLa = new QFormLayout(dialog);

    QLabel* label = new QLabel(dialog);
    QLabel* userLab = new QLabel(dialog);
    QLabel* passLab = new QLabel(dialog);
    userLab->setText(tr("Username: "));
    passLab->setText(tr("Password: "));

    QLineEdit* user = new QLineEdit(dialog);
    QLineEdit* pass = new QLineEdit(dialog);
    pass->setEchoMode(QLineEdit::Password);

    QDialogButtonBox* box = new QDialogButtonBox(dialog);
    box->addButton(QDialogButtonBox::Ok);
    box->addButton(QDialogButtonBox::Cancel);
    connect(box, SIGNAL(rejected()), dialog, SLOT(reject()));
    connect(box, SIGNAL(accepted()), dialog, SLOT(accept()));

    label->setText(tr("A username and password are being requested by proxy %1. ").arg(proxyHost));
    formLa->addRow(label);
    formLa->addRow(userLab, user);
    formLa->addRow(passLab, pass);
    formLa->addWidget(box);

    if (dialog->exec() != QDialog::Accepted) {
        return;
    }

    auth->setUser(user->text());
    auth->setPassword(pass->text());
}

void WebPage::dbQuotaExceeded(QWebEngineFrame* frame)
{
}

#ifdef USE_QTWEBKIT_2_2
void WebPage::appCacheQuotaExceeded(QWebEngineSecurityOrigin* origin, quint64 originalQuota)
{
}

void WebPage::featurePermissionRequested(QWebEngineFrame* frame, const QWebEnginePage::Feature &feature)
{
}
#endif // USE_QTWEBKIT_2_2

bool WebPage::event(QEvent* event)
{
    if (event->type() == QEvent::Leave) {
        // QWebEnginePagePrivate::leaveEvent():
        // Fake a mouse move event just outside of the widget, since all
        // the interesting mouse-out behavior like invalidating scrollbars
        // is handled by the WebKit event handler's mouseMoved function.

        // However, its implementation fake mouse move event on QCursor::pos()
        // position that is in global screen coordinates. So instead of
        // really faking it, it just creates mouse move event somewhere in
        // page. It can for example focus a link, and then link url gets
        // stuck in status bar message.

        // So we are faking mouse move event with proper coordinates for
        // so called "just outside of the widget" position

        const QPoint cursorPos = view()->mapFromGlobal(QCursor::pos());
        QPoint mousePos;

        if (cursorPos.y() < 0) {
            // Left on top
            mousePos = QPoint(cursorPos.x(), -1);
        }
        else if (cursorPos.x() < 0) {
            // Left on left
            mousePos = QPoint(-1, cursorPos.y());
        }
        else if (cursorPos.y() > view()->height()) {
            // Left on bottom
            mousePos = QPoint(cursorPos.x(), view()->height() + 1);
        }
        else {
            // Left on right
            mousePos = QPoint(view()->width() + 1, cursorPos.y());
        }

        QMouseEvent fakeEvent(QEvent::MouseMove, mousePos, Qt::NoButton, Qt::NoButton, Qt::NoModifier);
        return QWebEnginePage::event(&fakeEvent);
    }

    return QWebEnginePage::event(event);
}

void WebPage::setSSLCertificate(const QSslCertificate &cert)
{
    //    if (cert != m_SslCert)
    m_sslCert = cert;
}

QSslCertificate WebPage::sslCertificate()
{
    if (url().scheme() == QLatin1String("https") && QzTools::isCertificateValid(m_sslCert)) {
        return m_sslCert;
    }

    return QSslCertificate();
}

bool WebPage::acceptNavigationRequest(QWebEngineFrame* frame, const QNetworkRequest &request, NavigationType type)
{
    m_lastRequestType = type;
    m_lastRequestUrl = request.url();

    if (type == QWebEnginePage::NavigationTypeFormResubmitted) {
        // Don't show this dialog if app is still starting
        if (!view() || !view()->isVisible()) {
            return false;
        }
        QString message = tr("To show this page, QupZilla must resend request which do it again \n"
                             "(like searching on making an shopping, which has been already done.)");
        bool result = (QMessageBox::question(view(), tr("Confirm form resubmission"),
                                             message, QMessageBox::Yes | QMessageBox::No, QMessageBox::No) == QMessageBox::Yes);
        if (!result) {
            return false;
        }
    }

    bool accept = QWebEnginePage::acceptNavigationRequest(frame, request, type);
    return accept;
}

void WebPage::populateNetworkRequest(QNetworkRequest &request)
{
    WebPage* pagePointer = this;

    QVariant variant = QVariant::fromValue((void*) pagePointer);
    request.setAttribute((QNetworkRequest::Attribute)(QNetworkRequest::User + 100), variant);

    if (m_lastRequestUrl == request.url()) {
        request.setAttribute((QNetworkRequest::Attribute)(QNetworkRequest::User + 101), m_lastRequestType);
        if (m_lastRequestType == NavigationTypeLinkClicked) {
            request.setRawHeader("X-QupZilla-UserLoadAction", QByteArray("1"));
        }
    }
}

QWebEnginePage* WebPage::createWindow(QWebEnginePage::WebWindowType type)
{
    if (m_view) {
        return new PopupWebPage(type, m_view->mainWindow());
    }

    if (PopupWebPage* popupPage = qobject_cast<PopupWebPage*>(this)) {
        return new PopupWebPage(type, popupPage->mainWindow());
    }

    return 0;
}

QObject* WebPage::createPlugin(const QString &classid, const QUrl &url,
                               const QStringList &paramNames, const QStringList &paramValues)
{
    return 0;
}

void WebPage::cleanBlockedObjects()
{
}

bool WebPage::supportsExtension(Extension extension) const
{
    Q_UNUSED(extension)

    return true;
}

bool WebPage::extension(Extension extension, const ExtensionOption* option, ExtensionReturn* output)
{
    return true;
}

bool WebPage::javaScriptPrompt(QWebEngineFrame* originatingFrame, const QString &msg, const QString &defaultValue, QString* result)
{
#ifndef NONBLOCK_JS_DIALOGS
    return QWebEnginePage::javaScriptPrompt(originatingFrame, msg, defaultValue, result);
#else
    if (m_runningLoop) {
        return false;
    }

    WebView* webView = qobject_cast<WebView*>(this->view());
    ResizableFrame* widget = new ResizableFrame(webView->overlayForJsAlert());

    widget->setObjectName("jsFrame");
    Ui_jsPrompt* ui = new Ui_jsPrompt();
    ui->setupUi(widget);
    ui->message->setText(msg);
    ui->lineEdit->setText(defaultValue);
    ui->lineEdit->setFocus();
    widget->resize(this->viewportSize());
    widget->show();

    connect(webView, SIGNAL(viewportResized(QSize)), widget, SLOT(slotResize(QSize)));
    connect(ui->lineEdit, SIGNAL(returnPressed()), ui->buttonBox->button(QDialogButtonBox::Ok), SLOT(animateClick()));

    QEventLoop eLoop;
    m_runningLoop = &eLoop;
    connect(ui->buttonBox, SIGNAL(clicked(QAbstractButton*)), &eLoop, SLOT(quit()));

    if (eLoop.exec() == 1) {
        return result;
    }
    m_runningLoop = 0;

    QString x = ui->lineEdit->text();
    bool _result = ui->buttonBox->clickedButtonRole() == QDialogButtonBox::AcceptRole;
    *result = x;

    delete widget;
    webView->setFocus();

    return _result;
#endif
}

bool WebPage::javaScriptConfirm(QWebEngineFrame* originatingFrame, const QString &msg)
{
#ifndef NONBLOCK_JS_DIALOGS
    return QWebEnginePage::javaScriptConfirm(originatingFrame, msg);
#else
    if (m_runningLoop) {
        return false;
    }

    WebView* webView = qobject_cast<WebView*>(this->view());
    ResizableFrame* widget = new ResizableFrame(webView->overlayForJsAlert());

    widget->setObjectName("jsFrame");
    Ui_jsConfirm* ui = new Ui_jsConfirm();
    ui->setupUi(widget);
    ui->message->setText(msg);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setFocus();
    widget->resize(this->viewportSize());
    widget->show();

    connect(webView, SIGNAL(viewportResized(QSize)), widget, SLOT(slotResize(QSize)));

    QEventLoop eLoop;
    m_runningLoop = &eLoop;
    connect(ui->buttonBox, SIGNAL(clicked(QAbstractButton*)), &eLoop, SLOT(quit()));

    if (eLoop.exec() == 1) {
        return false;
    }
    m_runningLoop = 0;

    bool result = ui->buttonBox->clickedButtonRole() == QDialogButtonBox::AcceptRole;

    delete widget;
    webView->setFocus();

    return result;
#endif
}

void WebPage::javaScriptAlert(QWebEngineFrame* originatingFrame, const QString &msg)
{
    Q_UNUSED(originatingFrame)

    if (m_blockAlerts || m_runningLoop) {
        return;
    }

#ifndef NONBLOCK_JS_DIALOGS
    QString title = tr("JavaScript alert");
    if (!url().host().isEmpty()) {
        title.append(QString(" - %1").arg(url().host()));
    }

    CheckBoxDialog dialog(QDialogButtonBox::Ok, view());
    dialog.setWindowTitle(title);
    dialog.setText(msg);
    dialog.setCheckBoxText(tr("Prevent this page from creating additional dialogs"));
    dialog.setIcon(qIconProvider->standardIcon(QStyle::SP_MessageBoxInformation));
    dialog.exec();

    m_blockAlerts = dialog.isChecked();

#else
    WebView* webView = qobject_cast<WebView*>(this->view());
    ResizableFrame* widget = new ResizableFrame(webView->overlayForJsAlert());

    widget->setObjectName("jsFrame");
    Ui_jsAlert* ui = new Ui_jsAlert();
    ui->setupUi(widget);
    ui->message->setText(msg);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setFocus();
    widget->resize(this->viewportSize());
    widget->show();

    connect(webView, SIGNAL(viewportResized(QSize)), widget, SLOT(slotResize(QSize)));

    QEventLoop eLoop;
    m_runningLoop = &eLoop;
    connect(ui->buttonBox, SIGNAL(clicked(QAbstractButton*)), &eLoop, SLOT(quit()));

    if (eLoop.exec() == 1) {
        return;
    }
    m_runningLoop = 0;

    m_blockAlerts = ui->preventAlerts->isChecked();

    delete widget;

    webView->setFocus();
#endif
}

void WebPage::setJavaScriptEnabled(bool enabled)
{
}

QString WebPage::chooseFile(QWebEngineFrame* originatingFrame, const QString &oldFile)
{
    QString suggFileName;

    if (oldFile.isEmpty()) {
        suggFileName = s_lastUploadLocation;
    }
    else {
        suggFileName = oldFile;
    }

    const QString fileName = QzTools::getOpenFileName("WebPage-ChooseFile", this->view(), tr("Choose file..."), suggFileName);

    if (!fileName.isEmpty()) {
        s_lastUploadLocation = fileName;

        // Check if we can read from file
        QFile file(fileName);
        if (!file.open(QFile::ReadOnly)) {
            const QString msg = tr("Cannot read data from <b>%1</b>. Upload was cancelled!").arg(fileName);
            QMessageBox::critical(view(), tr("Cannot read file!"), msg);
            return QString();
        }
    }

    return fileName;
}

bool WebPage::isPointerSafeToUse(WebPage* page)
{
    // Pointer to WebPage is passed with every QNetworkRequest casted to void*
    // So there is no way to test whether pointer is still valid or not, except
    // this hack.

    return page == 0 ? false : s_livingPages.contains(page);
}

void WebPage::disconnectObjects()
{
    if (m_runningLoop) {
        m_runningLoop->exit(1);
        m_runningLoop = 0;
    }

    s_livingPages.removeOne(this);

    disconnect(this);
}

WebPage::~WebPage()
{
    if (m_runningLoop) {
        m_runningLoop->exit(1);
        m_runningLoop = 0;
    }

    s_livingPages.removeOne(this);
}
