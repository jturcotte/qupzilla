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
#ifndef POPUPWEBPAGE_H
#define POPUPWEBPAGE_H

#include "qz_namespace.h"
#include "webpage.h"

class QupZilla;

class QT_QUPZILLA_EXPORT PopupWebPage : public WebPage
{
    Q_OBJECT
public:
    explicit PopupWebPage(WebWindowType type, QupZilla* mainClass);

    QupZilla* mainWindow() const;

private slots:
    void slotGeometryChangeRequested(const QRect &rect);

    void slotLoadStarted();
    void slotLoadProgress(int prog);
    void slotLoadFinished(bool state);

    void checkBehaviour();

private:
    QupZilla* p_QupZilla;
    QWebEnginePage::WebWindowType m_type;

    QRect m_geometry;

    bool m_isLoading;
    bool m_progress;
};

#endif // POPUPWEBPAGE_H
