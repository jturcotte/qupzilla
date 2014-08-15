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
#include "popupwebpage.h"
#include "popupwebview.h"
#include "popupwindow.h"
#include "qupzilla.h"
#include "tabwidget.h"
#include "tabbedwebview.h"

#include <QTimer>
#include <QStatusBar>

// Wrapper class to detect whether window is opened from JavaScript window.open method
// It has to be done this way, because QtWebKit has really bad API when it comes to opening
// new windows.
//
// Got an idea how to determine it from kWebKitPart.

PopupWebPage::PopupWebPage(QWebEnginePage::WebWindowType type, QupZilla* mainClass)
    : WebPage()
    , p_QupZilla(mainClass)
    , m_type(type)
    , m_isLoading(false)
    , m_progress(0)
{
    connect(this, SIGNAL(geometryChangeRequested(QRect)), this, SLOT(slotGeometryChangeRequested(QRect)));

    connect(this, SIGNAL(loadStarted()), this, SLOT(slotLoadStarted()));
    connect(this, SIGNAL(loadProgress(int)), this, SLOT(slotLoadProgress(int)));
    connect(this, SIGNAL(loadFinished(bool)), this, SLOT(slotLoadFinished(bool)));

    QTimer::singleShot(0, this, SLOT(checkBehaviour()));
}

QupZilla* PopupWebPage::mainWindow() const
{
    return p_QupZilla;
}

void PopupWebPage::slotGeometryChangeRequested(const QRect &rect)
{
    m_geometry = rect;
}

void PopupWebPage::slotLoadStarted()
{
    m_isLoading = true;
    m_progress = 0;
}

void PopupWebPage::slotLoadProgress(int prog)
{
    m_progress = prog;
}

void PopupWebPage::slotLoadFinished(bool state)
{
    Q_UNUSED(state)

    m_isLoading = false;
    m_progress = 0;
}

void PopupWebPage::checkBehaviour()
{
    if (m_type == QWebEnginePage::WebDialog) {
        PopupWebView* view = new PopupWebView;
        view->setWebPage(this);

        PopupWindow* popup = new PopupWindow(view);
        popup->setWindowGeometry(m_geometry);
        popup->show();

        if (m_isLoading) {
            view->fakeLoadingProgress(m_progress);
        }

        p_QupZilla->addDeleteOnCloseWidget(popup);

        disconnect(this, SIGNAL(geometryChangeRequested(QRect)), this, SLOT(slotGeometryChangeRequested(QRect)));

        disconnect(this, SIGNAL(loadStarted()), this, SLOT(slotLoadStarted()));
        disconnect(this, SIGNAL(loadProgress(int)), this, SLOT(slotLoadProgress(int)));
        disconnect(this, SIGNAL(loadFinished(bool)), this, SLOT(slotLoadFinished(bool)));
    }
    else {
        int index = p_QupZilla->tabWidget()->addView(QUrl(), Qz::NT_CleanSelectedTab);
        TabbedWebView* view = p_QupZilla->weView(index);
        view->setWebPage(this);
        if (m_type == QWebEnginePage::WebBrowserWindow)
            p_QupZilla->tabWidget()->detachTab(index);

        if (m_isLoading) {
            view->fakeLoadingProgress(m_progress);
        }
    }
}
