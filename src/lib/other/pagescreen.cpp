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
#include "pagescreen.h"
#include "ui_pagescreen.h"
#include "tabbedwebview.h"
#include "webpage.h"
#include "qztools.h"
#include "qupzilla.h"
#include "settings.h"

#include <QFileDialog>
#include <QMessageBox>
#include <QLabel>
#include <QTimer>
#include <QMovie>
#include <QPushButton>
#include <QCloseEvent>
#include <QPrinter>

#if QT_VERSION >= 0x050000
#include <QtConcurrent/QtConcurrentRun>
#else
#include <QtConcurrentRun>
#endif

PageScreen::PageScreen(WebView* view, QWidget* parent)
    : QDialog(parent)
    , ui(new Ui::PageScreen)
    , m_view(view)
    , m_imageScaling(0)
{
    setAttribute(Qt::WA_DeleteOnClose);
    ui->setupUi(this);

    m_formats[0] = QLatin1String("PNG");
    m_formats[1] = QLatin1String("BMP");
    m_formats[2] = QLatin1String("JPG");
    m_formats[3] = QLatin1String("PPM");
    m_formats[4] = QLatin1String("TIFF");
    m_formats[5] = QLatin1String("PDF");

    QHashIterator<int, QString> i(m_formats);
    while (i.hasNext()) {
        i.next();
        ui->formats->addItem(tr("Save as %1").arg(i.value()));
    }

    // Set png as a default format
    m_pageTitle = m_view->title();

    Settings settings;
    const QString name = QzTools::filterCharsFromFilename(m_pageTitle).replace(QLatin1Char(' '), QLatin1Char('_'));
    const QString path = settings.value("FileDialogPaths/PageScreen-Location", QDir::homePath()).toString();
    ui->location->setText(QString("%1/%2.png").arg(path, name));

    QMovie* mov = new QMovie(":html/loading.gif");
    ui->label->setMovie(mov);
    mov->start();

    connect(ui->changeLocation, SIGNAL(clicked()), this, SLOT(changeLocation()));
    connect(ui->formats, SIGNAL(currentIndexChanged(int)), this, SLOT(formatChanged()));
    connect(ui->buttonBox->button(QDialogButtonBox::Save), SIGNAL(clicked()), this, SLOT(dialogAccepted()));
    connect(ui->buttonBox->button(QDialogButtonBox::Cancel), SIGNAL(clicked()), this, SLOT(close()));

    QTimer::singleShot(200, this, SLOT(createThumbnail()));
}

void PageScreen::formatChanged()
{
    QString text = ui->location->text();
    int pos = text.lastIndexOf(QLatin1Char('.'));

    if (pos > -1) {
        text = text.left(pos + 1) + m_formats[ui->formats->currentIndex()].toLower();
    }
    else {
        text.append(QLatin1Char('.') + m_formats[ui->formats->currentIndex()].toLower());
    }

    ui->location->setText(text);
}

void PageScreen::changeLocation()
{
    const QString name = QzTools::filterCharsFromFilename(m_pageTitle).replace(QLatin1Char(' '), QLatin1Char('_'));
    const QString suggestedPath = QString("%1/%2.%3").arg(QDir::homePath(), name, m_formats[ui->formats->currentIndex()].toLower());

    const QString path = QzTools::getOpenFileName("PageScreen-Location", this, tr("Choose location..."), suggestedPath);

    if (!path.isEmpty()) {
        ui->location->setText(path);
    }
}

void PageScreen::dialogAccepted()
{
    if (!ui->location->text().isEmpty()) {
        if (QFile::exists(ui->location->text())) {
            const QString text = tr("File '%1' already exists. Do you want to overwrite it?").arg(ui->location->text());
            QMessageBox::StandardButton button = QMessageBox::warning(this, tr("File already exists"), text,
                                                 QMessageBox::Yes | QMessageBox::No, QMessageBox::No);

            if (button != QMessageBox::Yes) {
                return;
            }
        }

        QApplication::setOverrideCursor(Qt::WaitCursor);

        const QString format = m_formats[ui->formats->currentIndex()];
        if (format == QLatin1String("PDF")) {
            saveAsDocument(format);
        }
        else {
            saveAsImage(format);
        }

        QApplication::restoreOverrideCursor();

        close();
    }
}

void PageScreen::saveAsImage(const QString &format)
{
    const QString suffix = QLatin1Char('.') + format.toLower();

    QString pathWithoutSuffix = ui->location->text();
    if (pathWithoutSuffix.endsWith(suffix, Qt::CaseInsensitive)) {
        pathWithoutSuffix = pathWithoutSuffix.mid(0, pathWithoutSuffix.length() - suffix.length());
    }

    if (m_pageImages.count() == 1) {
        m_pageImages.first().save(pathWithoutSuffix + suffix, format.toUtf8());
    }
    else {
        int part = 1;
        foreach (const QImage &image, m_pageImages) {
            const QString fileName = pathWithoutSuffix + ".part" + QString::number(part);
            image.save(fileName + suffix, format.toUtf8());
            part++;
        }
    }
}

void PageScreen::saveAsDocument(const QString &format)
{
    const QString suffix = QLatin1Char('.') + format.toLower();

    QString pathWithoutSuffix = ui->location->text();
    if (pathWithoutSuffix.endsWith(suffix, Qt::CaseInsensitive)) {
        pathWithoutSuffix = pathWithoutSuffix.mid(0, pathWithoutSuffix.length() - suffix.length());
    }

    QPrinter printer;
    printer.setCreator(QupZilla::tr("QupZilla %1 (%2)").arg(QupZilla::VERSION, QupZilla::WWWADDRESS));
    printer.setOutputFileName(pathWithoutSuffix + suffix);
    printer.setOutputFormat(QPrinter::PdfFormat);
    printer.setPaperSize(m_pageImages.first().size(), QPrinter::DevicePixel);
    printer.setPageMargins(0, 0, 0, 0, QPrinter::DevicePixel);
    printer.setFullPage(true);

    QPainter painter;
    painter.begin(&printer);

    for (int i = 0; i < m_pageImages.size(); ++i) {
        const QImage image = m_pageImages.at(i);
        painter.drawImage(0, 0, image);

        if (i != m_pageImages.size() - 1) {
            printer.newPage();
        }
    }

    painter.end();
}

void PageScreen::createThumbnail()
{
}

QImage PageScreen::scaleImage()
{
    QVector<QImage> scaledImages;
    int sumHeight = 0;

    foreach (const QImage &image, m_pageImages) {
        QImage scaled = image.scaledToWidth(450, Qt::SmoothTransformation);

        scaledImages.append(scaled);
        sumHeight += scaled.height();
    }

    QImage finalImage(QSize(450, sumHeight), QImage::Format_ARGB32_Premultiplied);
    QPainter painter(&finalImage);

    int offset = 0;
    foreach (const QImage &image, scaledImages) {
        painter.drawImage(0, offset, image);
        offset += image.height();
    }

    return finalImage;
}

void PageScreen::showImage()
{
    delete ui->label->movie();

    ui->label->setPixmap(QPixmap::fromImage(m_imageScaling->result()));
}

PageScreen::~PageScreen()
{
    delete ui;
}
