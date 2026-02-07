# -*- coding: utf-8 -*-
# -----------------------------------------------------------------
# Name:         sfwebui
# Purpose:      User interface class for use with a web browser
#
# Author:       Steve Micallef <steve@binarypool.com>
#
# Created:      30/09/2012
# Copyright:    (c) Steve Micallef 2012
# License:      MIT
# -----------------------------------------------------------------
import csv
import html
import json
import logging
import multiprocessing as mp
import os
import random
import re
import time
from copy import deepcopy
from io import StringIO
from operator import itemgetter
from typing import Optional

from fastapi import FastAPI, Form, Query, Request, UploadFile, File
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

import secure

from sflib import SpiderFoot
from spiderfoot import SpiderFootDb, SpiderFootHelpers, __version__
from spiderfoot.services import (
    ScanService, ConfigService, DataService,
    build_excel, clean_user_input,
)
from spiderfoot.logger import logListenerSetup, logWorkerSetup

mp.set_start_method("spawn", force=True)

# Footer messages displayed randomly
FOOTER_MESSAGES = [
    "<i class='glyphicon glyphicon-flash'></i>&nbsp;&nbsp;<a target=_new href='https://www.spiderfoot.net/hx'>Create a (free) SpiderFoot HX account in seconds and try it out for yourself.</a>",
    "<i class='glyphicon glyphicon-flash'></i>&nbsp;&nbsp;<a target=_new href='https://www.spiderfoot.net/open-source-vs-hx'>Learn about the difference between SpiderFoot and SpiderFoot HX.</a>",
    "<i class='glyphicon glyphicon-heart'></i>&nbsp;&nbsp;<a target=_new href='https://twitter.com/intent/follow?original_referer=https%3A%2F%2Fpublish.twitter.com%2F&ref_src=twsrc%5Etfw%7Ctwcamp%5Ebuttonembed%7Ctwterm%5Efollow%7Ctwgr%5Espiderfoot&screen_name=spiderfoot'>Follow SpiderFoot on Twitter for the latest updates.</a>",
    "<i class='glyphicon glyphicon-education'></i>&nbsp;&nbsp;<a target=_new href='https://www.spiderfoot.net/documentation'>Check out the SpiderFoot documentation to get more out of SpiderFoot.</a>",
    "<i class='glyphicon glyphicon-heart'></i>&nbsp;&nbsp;<a target=_new href='https://discord.gg/vyvztrG'>Join the SpiderFoot community Discord!</a>",
    "<i class='glyphicon glyphicon-console'></i>&nbsp;&nbsp;<a target=_new href='https://asciinema.org/~spiderfoot'>Did you know SpiderFoot also has a CLI? Check out our asciinema tutorials on how to use it.</a>",
    "<i class='glyphicon glyphicon-flash'></i>&nbsp;&nbsp;<a target=_new href='https://www.spiderfoot.net/hx'>Want more OSINT automation capabilities? Check out SpiderFoot HX.</a>",
    "<i class='glyphicon glyphicon-cloud'></i>&nbsp;&nbsp;<a target=_new href='https://www.spiderfoot.net/hx'>Don't want to manage your SpiderFoot installation yourself? Check out SpiderFoot HX.</a>",
    "<i class='glyphicon glyphicon-film'></i>&nbsp;&nbsp;<a target=_new href='https://www.youtube.com/channel/UCujtHhVLNeiJA_3F-lghD-w'>Check out our YouTube channel to see SpiderFoot HX in action.</a>",
]


def _urlize_step(text):
    """Custom Jinja2 filter to convert URLs in text to HTML links."""
    return re.sub(
        r'(https?://[^\s<>"\']+)',
        r'<a href="\1" target="_blank">\1</a>',
        str(text)
    )


def create_app(web_config: dict, config: dict, logging_queue=None) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        web_config: config settings for web interface (interface, port, root path)
        config: SpiderFoot config
        logging_queue: main SpiderFoot logging queue

    Returns:
        FastAPI: configured application instance
    """
    if not isinstance(config, dict):
        raise TypeError(f"config is {type(config)}; expected dict()")
    if not config:
        raise ValueError("config is empty")

    if not isinstance(web_config, dict):
        raise TypeError(f"web_config is {type(web_config)}; expected dict()")

    docroot = web_config.get('root', '/').rstrip('/')

    # Supplement defaults with saved configuration
    default_config = deepcopy(config)
    dbh = SpiderFootDb(default_config, init=True)
    sf = SpiderFoot(default_config)
    app_config = sf.configUnserialize(dbh.configGet(), default_config)

    # Set up logging
    if logging_queue is None:
        logging_queue = mp.Queue()
        logListenerSetup(logging_queue, app_config)
    logWorkerSetup(logging_queue)
    # Initialize services
    scan_service = ScanService(app_config, default_config, logging_queue)
    config_service = ConfigService(app_config, default_config)
    data_service = DataService(app_config)

    # Build security headers
    csp = (
        secure.ContentSecurityPolicy()
        .default_src("'self'")
        .script_src("'self'", "'unsafe-inline'", "blob:")
        .style_src("'self'", "'unsafe-inline'")
        .base_uri("'self'")
        .connect_src("'self'", "data:")
        .frame_src("'self'", 'data:')
        .img_src("'self'", "data:")
    )

    secure_headers = secure.Secure(
        server=secure.Server().set("server"),
        cache=secure.CacheControl().must_revalidate(),
        csp=csp,
        referrer=secure.ReferrerPolicy().no_referrer(),
    )

    app = FastAPI(title="SpiderFoot", version=__version__, docs_url=None, redoc_url=None)

    # Security headers middleware
    @app.middleware("http")
    async def add_security_headers(request: Request, call_next):
        response = await call_next(request)
        secure_headers.set_headers(response)
        return response

    # Static files
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "spiderfoot", "static")
    app.mount("/static", StaticFiles(directory=static_dir), name="static")

    # Templates
    template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "spiderfoot", "templates")
    templates = Jinja2Templates(directory=template_dir)
    templates.env.filters['urlize_step'] = _urlize_step

    def _tpl_ctx(request: Request, **kwargs):
        """Build common template context."""
        ctx = {
            "request": request,
            "docroot": docroot,
            "version": __version__,
            "footer_message": random.choice(FOOTER_MESSAGES),
        }
        ctx.update(kwargs)
        return ctx

    def _error_page(request: Request, message: str):
        return templates.TemplateResponse("error.html", _tpl_ctx(request, message=message))

    # =====================================================================
    # HTML PAGES
    # =====================================================================

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        return templates.TemplateResponse("scanlist.html", _tpl_ctx(request, pageid="SCANLIST"))

    @app.get("/newscan", response_class=HTMLResponse)
    async def newscan(request: Request):
        dbh = SpiderFootDb(app_config)
        types = dbh.eventTypes()
        return templates.TemplateResponse("newscan.html", _tpl_ctx(
            request, pageid='NEWSCAN', types=types,
            modules=app_config['__modules__'], scanname="",
            selectedmods="", scantarget="",
        ))

    @app.get("/clonescan", response_class=HTMLResponse)
    async def clonescan(request: Request, id: str = Query(...)):
        dbh = SpiderFootDb(app_config)
        types = dbh.eventTypes()
        info = dbh.scanInstanceGet(id)

        if not info:
            return _error_page(request, "Invalid scan ID.")

        scanconfig = dbh.scanConfigGet(id)
        scanname = info[0]
        scantarget = info[1]

        if scanname == "" or scantarget == "" or len(scanconfig) == 0:
            return _error_page(request, "Something went wrong internally.")

        target_type = SpiderFootHelpers.targetTypeFromString(scantarget)
        if target_type is None:
            scantarget = "&quot;" + scantarget + "&quot;"

        modlist = scanconfig['_modulesenabled'].split(',')

        return templates.TemplateResponse("newscan.html", _tpl_ctx(
            request, pageid='NEWSCAN', types=types,
            modules=app_config['__modules__'], selectedmods=modlist,
            scanname=str(scanname), scantarget=str(scantarget),
        ))

    @app.get("/scaninfo", response_class=HTMLResponse)
    async def scaninfo_page(request: Request, id: str = Query(...)):
        dbh = SpiderFootDb(app_config)
        res = dbh.scanInstanceGet(id)
        if res is None:
            return _error_page(request, "Scan ID not found.")

        return templates.TemplateResponse("scaninfo.html", _tpl_ctx(
            request, id=id, name=html.escape(res[0]), status=res[5], pageid="SCANLIST",
        ))

    @app.get("/opts", response_class=HTMLResponse)
    async def opts_page(request: Request, updated: str = None):
        config_service.token = random.SystemRandom().randint(0, 99999999)
        return templates.TemplateResponse("opts.html", _tpl_ctx(
            request, opts=app_config, pageid='SETTINGS',
            token=config_service.token, updated=updated,
        ))

    # =====================================================================
    # SCAN API ENDPOINTS
    # =====================================================================

    @app.post("/startscan")
    async def startscan(
        request: Request,
        scanname: str = Form(""),
        scantarget: str = Form(""),
        modulelist: str = Form(""),
        typelist: str = Form(""),
        usecase: str = Form(""),
    ):
        success, message, scan_id = scan_service.start_scan(scanname, scantarget, modulelist, typelist, usecase)

        if not success:
            accept = request.headers.get('Accept', '')
            if 'application/json' in accept:
                return JSONResponse(["ERROR", message])
            return _error_page(request, message)

        accept = request.headers.get('Accept', '')
        if 'application/json' in accept:
            return JSONResponse(["SUCCESS", scan_id])

        return RedirectResponse(url=f"{docroot}/scaninfo?id={scan_id}", status_code=302)

    @app.get("/stopscan")
    async def stopscan(id: str = Query("")):
        success, error_code, message = scan_service.stop_scan(id)
        if not success:
            return JSONResponse({'error': {'http_status': error_code, 'message': message}}, status_code=int(error_code))
        return JSONResponse("")

    @app.get("/scandelete")
    async def scandelete(id: str = Query("")):
        success, error_code, message = scan_service.delete_scan(id)
        if not success:
            return JSONResponse({'error': {'http_status': error_code, 'message': message}}, status_code=int(error_code))
        return JSONResponse("")

    @app.get("/rerunscan")
    async def rerunscan(request: Request, id: str = Query(...)):
        success, message, new_scan_id = scan_service.rerun_scan(id)
        if not success:
            return _error_page(request, message)
        return RedirectResponse(url=f"{docroot}/scaninfo?id={new_scan_id}", status_code=302)

    @app.get("/rerunscanmulti")
    async def rerunscanmulti(request: Request, ids: str = Query(...)):
        for scan_id in ids.split(","):
            success, message, new_scan_id = scan_service.rerun_scan(scan_id)
            if not success:
                return _error_page(request, message)
        return templates.TemplateResponse("scanlist.html", _tpl_ctx(request, rerunscans=True, pageid="SCANLIST"))

    # =====================================================================
    # DATA PROVIDER ENDPOINTS (JSON)
    # =====================================================================

    @app.api_route("/scanlist", methods=["GET", "POST"])
    async def scanlist():
        return JSONResponse(scan_service.list_scans())

    @app.api_route("/scanstatus", methods=["GET", "POST"])
    async def scanstatus(id: str = Query(...)):
        return JSONResponse(scan_service.scan_status(id))

    @app.api_route("/scansummary", methods=["GET", "POST"])
    async def scansummary(id: str = Query(...), by: str = Query(...)):
        return JSONResponse(scan_service.scan_summary(id, by))

    @app.api_route("/scancorrelations", methods=["GET", "POST"])
    async def scancorrelations(id: str = Query(...)):
        return JSONResponse(scan_service.scan_correlations(id))

    @app.api_route("/scaneventresults", methods=["GET", "POST"])
    @app.post("/scaneventresults")
    async def scaneventresults(
        request: Request,
        id: str = Query(None),
        eventType: str = Query(None),
        filterfp: bool = Query(False),
        correlationId: str = Query(None),
    ):
        # Support POST form data (used by sfcli.py)
        if request.method == "POST":
            form = await request.form()
            id = form.get("id", id)
            eventType = form.get("eventType", eventType)
            filterfp = bool(form.get("filterfp", filterfp))
            correlationId = form.get("correlationId", correlationId)
        return JSONResponse(scan_service.scan_event_results(id, eventType, filterfp, correlationId))

    @app.api_route("/scaneventresultsunique", methods=["GET", "POST"])
    @app.post("/scaneventresultsunique")
    async def scaneventresultsunique(
        request: Request,
        id: str = Query(None),
        eventType: str = Query(None),
        filterfp: bool = Query(False),
    ):
        if request.method == "POST":
            form = await request.form()
            id = form.get("id", id)
            eventType = form.get("eventType", eventType)
            filterfp = bool(form.get("filterfp", filterfp))
        return JSONResponse(scan_service.scan_event_results_unique(id, eventType, filterfp))

    @app.api_route("/scanopts", methods=["GET", "POST"])
    @app.post("/scanopts")
    async def scanopts(request: Request, id: str = Query(None)):
        if request.method == "POST":
            form = await request.form()
            id = form.get("id", id)
        return JSONResponse(scan_service.scan_config(id))

    @app.api_route("/scanlog", methods=["GET", "POST"])
    @app.post("/scanlog")
    async def scanlog(
        request: Request,
        id: str = Query(None),
        limit: str = Query(None),
        rowId: str = Query(None),
        reverse: str = Query(None),
    ):
        if request.method == "POST":
            form = await request.form()
            id = form.get("id", id)
            limit = form.get("limit", limit)
            rowId = form.get("rowId", rowId)
            reverse = form.get("reverse", reverse)
        return JSONResponse(scan_service.scan_logs(id, limit, rowId, reverse))

    @app.api_route("/scanerrors", methods=["GET", "POST"])
    @app.post("/scanerrors")
    async def scanerrors(request: Request, id: str = Query(None), limit: str = Query(None)):
        if request.method == "POST":
            form = await request.form()
            id = form.get("id", id)
            limit = form.get("limit", limit)
        return JSONResponse(scan_service.scan_errors(id, limit))

    @app.api_route("/scanhistory", methods=["GET", "POST"])
    async def scanhistory(id: str = Query(None)):
        if not id:
            return JSONResponse({'error': {'http_status': '404', 'message': 'No scan specified'}}, status_code=404)
        return JSONResponse(scan_service.scan_history(id))

    @app.api_route("/scanelementtypediscovery", methods=["GET", "POST"])
    @app.post("/scanelementtypediscovery")
    async def scanelementtypediscovery(request: Request, id: str = Query(None), eventType: str = Query(None)):
        if request.method == "POST":
            form = await request.form()
            id = form.get("id", id)
            eventType = form.get("eventType", eventType)
        return JSONResponse(scan_service.scan_element_type_discovery(id, eventType))

    # =====================================================================
    # SEARCH
    # =====================================================================

    @app.get("/search")
    @app.post("/search")
    async def search(
        request: Request,
        id: str = Query(None),
        eventType: str = Query(None),
        value: str = Query(None),
    ):
        if request.method == "POST":
            form = await request.form()
            id = form.get("id", id)
            eventType = form.get("eventType", eventType)
            value = form.get("value", value)
        try:
            return JSONResponse(data_service.search(id, eventType, value))
        except Exception:
            return JSONResponse([])

    # =====================================================================
    # FALSE POSITIVE
    # =====================================================================

    @app.post("/resultsetfp")
    async def resultsetfp(
        request: Request,
        id: str = Form(""),
        resultids: str = Form(""),
        fp: str = Form(""),
    ):
        status, message = scan_service.set_false_positive(id, resultids, fp)
        return JSONResponse([status, message])

    # =====================================================================
    # EXPORT ENDPOINTS
    # =====================================================================

    @app.get("/scanexportlogs")
    async def scanexportlogs(id: str = Query(...), dialect: str = Query("excel")):
        dbh = SpiderFootDb(app_config)
        try:
            data = dbh.scanLogs(id, None, None, True)
        except Exception:
            return Response("Scan ID not found.", media_type="text/html")

        if not data:
            return Response("Scan ID not found.", media_type="text/html")

        fileobj = StringIO()
        parser = csv.writer(fileobj, dialect=dialect)
        parser.writerow(["Date", "Component", "Type", "Event", "Event ID"])
        for row in data:
            parser.writerow([
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0] / 1000)),
                str(row[1]), str(row[2]), str(row[3]), row[4]
            ])

        return Response(
            content=fileobj.getvalue().encode('utf-8'),
            media_type="application/csv",
            headers={
                'Content-Disposition': f"attachment; filename=SpiderFoot-{id}.log.csv",
                'Pragma': 'no-cache',
            },
        )

    @app.get("/scaneventresultexport")
    async def scaneventresultexport(
        request: Request,
        id: str = Query(...),
        type: str = Query("ALL"),
        filetype: str = Query("csv"),
        dialect: str = Query("excel"),
    ):
        dbh = SpiderFootDb(app_config)
        data = dbh.scanResultEvent(id, type)

        if filetype.lower() in ["xlsx", "excel"]:
            rows = []
            for row in data:
                if row[4] == "ROOT":
                    continue
                lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
                datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
                rows.append([lastseen, str(row[4]), str(row[3]), str(row[2]), row[13], datafield])

            return Response(
                content=build_excel(rows, ["Updated", "Type", "Module", "Source", "F/P", "Data"], sheet_name_index=1),
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={
                    'Content-Disposition': "attachment; filename=SpiderFoot.xlsx",
                    'Pragma': 'no-cache',
                },
            )

        if filetype.lower() == 'csv':
            fileobj = StringIO()
            parser = csv.writer(fileobj, dialect=dialect)
            parser.writerow(["Updated", "Type", "Module", "Source", "F/P", "Data"])
            for row in data:
                if row[4] == "ROOT":
                    continue
                lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
                datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
                parser.writerow([lastseen, str(row[4]), str(row[3]), str(row[2]), row[13], datafield])

            return Response(
                content=fileobj.getvalue().encode('utf-8'),
                media_type="application/csv",
                headers={
                    'Content-Disposition': "attachment; filename=SpiderFoot.csv",
                    'Pragma': 'no-cache',
                },
            )

        return _error_page(request, "Invalid export filetype.")

    @app.get("/scaneventresultexportmulti")
    @app.post("/scaneventresultexportmulti")
    async def scaneventresultexportmulti(
        request: Request,
        ids: str = Query(None),
        filetype: str = Query("csv"),
        dialect: str = Query("excel"),
    ):
        if request.method == "POST":
            form = await request.form()
            ids = form.get("ids", ids)
            filetype = form.get("filetype", filetype)

        dbh = SpiderFootDb(app_config)
        scaninfo = {}
        data = []
        scan_name = ""

        for scan_id in ids.split(','):
            scaninfo[scan_id] = dbh.scanInstanceGet(scan_id)
            if scaninfo[scan_id] is None:
                continue
            scan_name = scaninfo[scan_id][0]
            data = data + dbh.scanResultEvent(scan_id)

        if not data:
            return Response("", media_type="text/html")

        if filetype.lower() in ["xlsx", "excel"]:
            rows = []
            for row in data:
                if row[4] == "ROOT":
                    continue
                lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
                datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
                rows.append([scaninfo[row[12]][0], lastseen, str(row[4]), str(row[3]),
                            str(row[2]), row[13], datafield])

            if len(ids.split(',')) > 1 or scan_name == "":
                fname = "SpiderFoot.xlsx"
            else:
                fname = scan_name + "-SpiderFoot.xlsx"

            return Response(
                content=build_excel(rows, ["Scan Name", "Updated", "Type", "Module",
                                    "Source", "F/P", "Data"], sheet_name_index=2),
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={'Content-Disposition': f"attachment; filename={fname}", 'Pragma': 'no-cache'},
            )

        if filetype.lower() == 'csv':
            fileobj = StringIO()
            parser = csv.writer(fileobj, dialect=dialect)
            parser.writerow(["Scan Name", "Updated", "Type", "Module", "Source", "F/P", "Data"])
            for row in data:
                if row[4] == "ROOT":
                    continue
                lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
                datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
                parser.writerow([scaninfo[row[12]][0], lastseen, str(row[4]), str(row[3]),
                                str(row[2]), row[13], datafield])

            if len(ids.split(',')) > 1 or scan_name == "":
                fname = "SpiderFoot.csv"
            else:
                fname = scan_name + "-SpiderFoot.csv"

            return Response(
                content=fileobj.getvalue().encode('utf-8'),
                media_type="application/csv",
                headers={'Content-Disposition': f"attachment; filename={fname}", 'Pragma': 'no-cache'},
            )

        return _error_page(request, "Invalid export filetype.")

    @app.get("/scansearchresultexport")
    async def scansearchresultexport(
        request: Request,
        id: str = Query(...),
        eventType: str = Query(None),
        value: str = Query(None),
        filetype: str = Query("csv"),
        dialect: str = Query("excel"),
    ):
        search_data = data_service.search(id, eventType, value)
        if not search_data:
            return Response("", media_type="text/html")

        if filetype.lower() in ["xlsx", "excel"]:
            rows = []
            for row in search_data:
                if row[10] == "ROOT":
                    continue
                datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
                rows.append([row[0], str(row[10]), str(row[3]), str(row[2]), row[11], datafield])
            return Response(
                content=build_excel(rows, ["Updated", "Type", "Module", "Source", "F/P", "Data"], sheet_name_index=1),
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={'Content-Disposition': "attachment; filename=SpiderFoot.xlsx", 'Pragma': 'no-cache'},
            )

        if filetype.lower() == 'csv':
            fileobj = StringIO()
            parser = csv.writer(fileobj, dialect=dialect)
            parser.writerow(["Updated", "Type", "Module", "Source", "F/P", "Data"])
            for row in search_data:
                if row[10] == "ROOT":
                    continue
                datafield = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
                parser.writerow([row[0], str(row[10]), str(row[3]), str(row[2]), row[11], datafield])
            return Response(
                content=fileobj.getvalue().encode('utf-8'),
                media_type="application/csv",
                headers={'Content-Disposition': "attachment; filename=SpiderFoot.csv", 'Pragma': 'no-cache'},
            )

        return _error_page(request, "Invalid export filetype.")

    @app.get("/scancorrelationsexport")
    async def scancorrelationsexport(
        request: Request,
        id: str = Query(...),
        filetype: str = Query("csv"),
        dialect: str = Query("excel"),
    ):
        dbh = SpiderFootDb(app_config)
        try:
            scaninfo = dbh.scanInstanceGet(id)
            scan_name = scaninfo[0]
        except Exception:
            return JSONResponse(["ERROR", "Could not retrieve info for scan."])

        try:
            correlations = dbh.scanCorrelationList(id)
        except Exception:
            return JSONResponse(["ERROR", "Could not retrieve correlations for scan."])

        headings = ["Rule Name", "Correlation", "Risk", "Description"]

        if filetype.lower() in ["xlsx", "excel"]:
            rows = []
            for row in correlations:
                rows.append([row[2], row[1], row[3], row[5]])
            fname = f"{scan_name}-SpiderFoot-correlations.xlsx" if scan_name else "SpiderFoot-correlations.xlsx"
            return Response(
                content=build_excel(rows, headings, sheet_name_index=0),
                media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                headers={'Content-Disposition': f"attachment; filename={fname}", 'Pragma': 'no-cache'},
            )

        if filetype.lower() == 'csv':
            fileobj = StringIO()
            parser = csv.writer(fileobj, dialect=dialect)
            parser.writerow(headings)
            for row in correlations:
                parser.writerow([row[2], row[1], row[3], row[5]])
            fname = f"{scan_name}-SpiderFoot-correlations.csv" if scan_name else "SpiderFoot-correlations.csv"
            return Response(
                content=fileobj.getvalue().encode('utf-8'),
                media_type="application/csv",
                headers={'Content-Disposition': f"attachment; filename={fname}", 'Pragma': 'no-cache'},
            )

        return _error_page(request, "Invalid export filetype.")

    @app.get("/scanexportjsonmulti")
    @app.post("/scanexportjsonmulti")
    async def scanexportjsonmulti(request: Request, ids: str = Query(None)):
        if request.method == "POST":
            form = await request.form()
            ids = form.get("ids", ids)

        dbh = SpiderFootDb(app_config)
        scaninfo = []
        scan_name = ""

        for scan_id in ids.split(','):
            scan = dbh.scanInstanceGet(scan_id)
            if scan is None:
                continue
            scan_name = scan[0]

            for row in dbh.scanResultEvent(scan_id):
                lastseen = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0]))
                event_data = str(row[1]).replace("<SFURL>", "").replace("</SFURL>", "")
                if row[4] == "ROOT":
                    continue
                scaninfo.append({
                    "data": event_data,
                    "event_type": row[4],
                    "module": str(row[3]),
                    "source_data": str(row[2]),
                    "false_positive": row[13],
                    "last_seen": lastseen,
                    "scan_name": scan_name,
                    "scan_target": scan[1]
                })

        if len(ids.split(',')) > 1 or scan_name == "":
            fname = "SpiderFoot.json"
        else:
            fname = scan_name + "-SpiderFoot.json"

        return Response(
            content=json.dumps(scaninfo).encode('utf-8'),
            media_type="application/json; charset=utf-8",
            headers={'Content-Disposition': f"attachment; filename={fname}", 'Pragma': 'no-cache'},
        )

    @app.get("/scanviz")
    async def scanviz(id: str = Query(...), gexf: str = Query("0")):
        if not id:
            return Response("", media_type="text/html")

        dbh = SpiderFootDb(app_config)
        data = dbh.scanResultEvent(id, filterFp=True)
        scan = dbh.scanInstanceGet(id)

        if not scan:
            return Response("", media_type="text/html")

        scan_name = scan[0]
        root = scan[1]

        if gexf == "0":
            return JSONResponse(json.loads(SpiderFootHelpers.buildGraphJson([root], data)))

        fname = (scan_name + "SpiderFoot.gexf") if scan_name else "SpiderFoot.gexf"
        return Response(
            content=SpiderFootHelpers.buildGraphGexf([root], "SpiderFoot Export", data),
            media_type="application/gexf",
            headers={'Content-Disposition': f"attachment; filename={fname}", 'Pragma': 'no-cache'},
        )

    @app.get("/scanvizmulti")
    @app.post("/scanvizmulti")
    async def scanvizmulti(request: Request, ids: str = Query(None), gexf: str = Query("1")):
        if request.method == "POST":
            form = await request.form()
            ids = form.get("ids", ids)

        if not ids:
            return Response("", media_type="text/html")

        dbh = SpiderFootDb(app_config)
        data = []
        roots = []
        scan_name = ""

        for scan_id in ids.split(','):
            scan = dbh.scanInstanceGet(scan_id)
            if not scan:
                continue
            data = data + dbh.scanResultEvent(scan_id, filterFp=True)
            roots.append(scan[1])
            scan_name = scan[0]

        if not data:
            return Response("", media_type="text/html")

        if gexf == "0":
            return Response("", media_type="text/html")

        if len(ids.split(',')) > 1 or scan_name == "":
            fname = "SpiderFoot.gexf"
        else:
            fname = scan_name + "-SpiderFoot.gexf"

        return Response(
            content=SpiderFootHelpers.buildGraphGexf(roots, "SpiderFoot Export", data),
            media_type="application/gexf",
            headers={'Content-Disposition': f"attachment; filename={fname}", 'Pragma': 'no-cache'},
        )

    # =====================================================================
    # CONFIG ENDPOINTS
    # =====================================================================

    @app.get("/optsraw")
    async def optsraw():
        token, data = config_service.get_raw_config()
        return JSONResponse(['SUCCESS', {'token': token, 'data': data}])

    @app.get("/optsexport")
    async def optsexport(pattern: str = Query(None)):
        content = config_service.export_config(pattern)
        return Response(
            content=content,
            media_type="text/plain",
            headers={'Content-Disposition': 'attachment; filename="SpiderFoot.cfg"'},
        )

    @app.post("/savesettings")
    async def savesettings(
        request: Request,
        allopts: str = Form(""),
        token: str = Form(""),
        configFile: Optional[UploadFile] = File(None),
    ):
        config_file_contents = None
        if configFile and configFile.filename:
            contents = await configFile.read()
            if isinstance(contents, bytes):
                config_file_contents = contents.decode('utf-8')
            else:
                config_file_contents = contents

        success, message = config_service.save_settings(allopts, token, config_file_contents)

        if not success:
            return _error_page(request, message)

        return RedirectResponse(url=f"{docroot}/opts?updated=1", status_code=302)

    @app.post("/savesettingsraw")
    async def savesettingsraw(
        request: Request,
        allopts: str = Form(""),
        token: str = Form(""),
    ):
        status, message = config_service.save_settings_raw(allopts, token)
        return JSONResponse([status, message])

    # =====================================================================
    # META ENDPOINTS
    # =====================================================================

    @app.get("/ping")
    async def ping():
        return JSONResponse(["SUCCESS", __version__])

    @app.get("/modules")
    async def modules():
        ret = []
        modinfo = list(app_config['__modules__'].keys())
        if not modinfo:
            return JSONResponse(ret)
        modinfo.sort()
        for m in modinfo:
            if "__" in m:
                continue
            ret.append({'name': m, 'descr': app_config['__modules__'][m]['descr']})
        return JSONResponse(ret)

    @app.get("/eventtypes")
    async def eventtypes():
        dbh = SpiderFootDb(app_config)
        types = dbh.eventTypes()
        ret = []
        for r in types:
            ret.append([r[1], r[0]])
        return JSONResponse(sorted(ret, key=itemgetter(0)))

    @app.get("/correlationrules")
    async def correlationrules():
        ret = []
        rules = app_config.get('__correlationrules__')
        if not rules:
            return JSONResponse(ret)
        for r in rules:
            ret.append({
                'id': r['id'],
                'name': r['meta']['name'],
                'descr': r['meta']['description'],
                'risk': r['meta']['risk'],
            })
        return JSONResponse(ret)

    @app.post("/query")
    async def query_endpoint(query: str = Form("")):
        success, result = data_service.query(query)
        if not success:
            status_code = 400 if "Non-SELECT" in str(result) or "Invalid" in str(result) else 500
            return JSONResponse(
                {'error': {'http_status': str(status_code), 'message': result}},
                status_code=status_code,
            )
        return JSONResponse(result)

    @app.get("/vacuum")
    async def vacuum():
        status, message = scan_service.vacuum_db()
        return JSONResponse([status, message])

    return app


# =====================================================================
# Backward-compatible SpiderFootWebUi class for tests
# =====================================================================

class SpiderFootWebUi:
    """SpiderFoot web interface -- thin wrapper for backward compatibility with tests."""

    def __init__(self, web_config: dict, config: dict, loggingQueue=None):
        if not isinstance(config, dict):
            raise TypeError(f"config is {type(config)}; expected dict()")
        if not config:
            raise ValueError("config is empty")

        if not isinstance(web_config, dict):
            raise TypeError(f"web_config is {type(web_config)}; expected dict()")
        if not config:
            raise ValueError("web_config is empty")

        self.docroot = web_config.get('root', '/').rstrip('/')

        self.defaultConfig = deepcopy(config)
        dbh = SpiderFootDb(self.defaultConfig, init=True)
        sf = SpiderFoot(self.defaultConfig)
        self.config = sf.configUnserialize(dbh.configGet(), self.defaultConfig)

        if loggingQueue is None:
            self.loggingQueue = mp.Queue()
            logListenerSetup(self.loggingQueue, self.config)
        else:
            self.loggingQueue = loggingQueue
        logWorkerSetup(self.loggingQueue)
        self.log = logging.getLogger(f"spiderfoot.{__name__}")

        self.token = None

        self._scan_service = ScanService(self.config, self.defaultConfig, self.loggingQueue)
        self._config_service = ConfigService(self.config, self.defaultConfig)
        self._data_service = DataService(self.config)

        self._templates = Jinja2Templates(
            directory=os.path.join(os.path.dirname(os.path.abspath(__file__)), "spiderfoot", "templates")
        )
        self._templates.env.filters['urlize_step'] = _urlize_step

    def _render_template(self, template_name, **kwargs):
        ctx = {
            "docroot": self.docroot,
            "version": __version__,
            "footer_message": random.choice(FOOTER_MESSAGES),
        }
        ctx.update(kwargs)
        template = self._templates.env.get_template(template_name)
        return template.render(**ctx)

    def error_page(self):
        pass

    def error_page_401(self, status, message, traceback, version):
        return ""

    def error_page_404(self, status, message, traceback, version):
        return self._render_template("error.html", message='Not Found', status=status)

    def jsonify_error(self, status, message):
        return {'error': {'http_status': status, 'message': message}}

    def error(self, message):
        return self._render_template("error.html", message=message)

    def cleanUserInput(self, inputList):
        return clean_user_input(inputList)

    def searchBase(self, id=None, eventType=None, value=None):
        return self._data_service.search(id, eventType, value)

    def buildExcel(self, data, columnNames, sheetNameIndex=0):
        return build_excel(data, columnNames, sheetNameIndex)

    def scanexportlogs(self, id, dialect="excel"):
        dbh = SpiderFootDb(self.config)
        try:
            data = dbh.scanLogs(id, None, None, True)
        except Exception:
            return self.error("Scan ID not found.")

        if not data:
            return self.error("Scan ID not found.")

        fileobj = StringIO()
        parser = csv.writer(fileobj, dialect=dialect)
        parser.writerow(["Date", "Component", "Type", "Event", "Event ID"])
        for row in data:
            parser.writerow([
                time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(row[0] / 1000)),
                str(row[1]), str(row[2]), str(row[3]), row[4]
            ])
        return fileobj.getvalue().encode('utf-8')

    def scanopts(self, id):
        return self._scan_service.scan_config(id)

    def rerunscan(self, id):
        success, message, new_id = self._scan_service.rerun_scan(id)
        if not success:
            return self.error(message)
        return f"Scan {new_id} started"

    def newscan(self):
        dbh = SpiderFootDb(self.config)
        types = dbh.eventTypes()
        return self._render_template("newscan.html", pageid='NEWSCAN', types=types,
                                     modules=self.config['__modules__'], scanname="",
                                     selectedmods="", scantarget="")

    def clonescan(self, id):
        dbh = SpiderFootDb(self.config)
        types = dbh.eventTypes()
        info = dbh.scanInstanceGet(id)

        if not info:
            return self.error("Invalid scan ID.")

        scanconfig = dbh.scanConfigGet(id)
        scanname = info[0]
        scantarget = info[1]

        if scanname == "" or scantarget == "" or len(scanconfig) == 0:
            return self.error("Something went wrong internally.")

        target_type = SpiderFootHelpers.targetTypeFromString(scantarget)
        if target_type is None:
            scantarget = "&quot;" + scantarget + "&quot;"

        modlist = scanconfig['_modulesenabled'].split(',')

        return self._render_template("newscan.html", pageid='NEWSCAN', types=types,
                                     modules=self.config['__modules__'], selectedmods=modlist,
                                     scanname=str(scanname), scantarget=str(scantarget))

    def index(self):
        return self._render_template("scanlist.html", pageid='SCANLIST')

    def scaninfo(self, id):
        dbh = SpiderFootDb(self.config)
        res = dbh.scanInstanceGet(id)
        if res is None:
            return self.error("Scan ID not found.")
        return self._render_template("scaninfo.html", id=id, name=html.escape(res[0]),
                                     status=res[5], pageid="SCANLIST")

    def opts(self, updated=None):
        self.token = random.SystemRandom().randint(0, 99999999)
        self._config_service.token = self.token
        return self._render_template("opts.html", opts=self.config, pageid='SETTINGS',
                                     token=self.token, updated=updated)

    def optsexport(self, pattern=None):
        return self._config_service.export_config(pattern)

    def optsraw(self):
        token, data = self._config_service.get_raw_config()
        self.token = token
        return ['SUCCESS', {'token': token, 'data': data}]

    def scandelete(self, id):
        success, error_code, message = self._scan_service.delete_scan(id)
        if not success:
            return self.jsonify_error(error_code, message)
        return ""

    def savesettings(self, allopts, token, configFile=None):
        config_file_contents = None
        if configFile and hasattr(configFile, 'file') and configFile.file:
            contents = configFile.file.read()
            if isinstance(contents, bytes):
                config_file_contents = contents.decode('utf-8')
            else:
                config_file_contents = contents

        success, message = self._config_service.save_settings(allopts, token, config_file_contents)
        if not success:
            return self.error(message)
        return None

    def savesettingsraw(self, allopts, token):
        status, message = self._config_service.save_settings_raw(allopts, token)
        return json.dumps([status, message]).encode('utf-8')

    def reset_settings(self):
        return self._config_service.reset_settings()

    def eventtypes(self):
        dbh = SpiderFootDb(self.config)
        types = dbh.eventTypes()
        ret = []
        for r in types:
            ret.append([r[1], r[0]])
        return sorted(ret, key=itemgetter(0))

    def modules(self):
        ret = []
        modinfo = list(self.config['__modules__'].keys())
        if not modinfo:
            return ret
        modinfo.sort()
        for m in modinfo:
            if "__" in m:
                continue
            ret.append({'name': m, 'descr': self.config['__modules__'][m]['descr']})
        return ret

    def correlationrules(self):
        ret = []
        rules = self.config.get('__correlationrules__')
        if not rules:
            return ret
        for r in rules:
            ret.append({
                'id': r['id'],
                'name': r['meta']['name'],
                'descr': r['meta']['description'],
                'risk': r['meta']['risk'],
            })
        return ret

    def ping(self):
        return ["SUCCESS", __version__]

    def query(self, query):
        success, result = self._data_service.query(query)
        if not success:
            return self.jsonify_error('400' if 'Non-SELECT' in str(result) or 'Invalid' in str(result) else '500', result)
        return result

    def startscan(self, scanname, scantarget, modulelist, typelist, usecase):
        success, message, scan_id = self._scan_service.start_scan(scanname, scantarget, modulelist, typelist, usecase)
        if not success:
            return self.error(message)
        return f"Scan {scan_id} started"

    def stopscan(self, id):
        success, error_code, message = self._scan_service.stop_scan(id)
        if not success:
            return self.jsonify_error(error_code, message)
        return ""

    def scanlog(self, id, limit=None, rowId=None, reverse=None):
        return self._scan_service.scan_logs(id, limit, rowId, reverse)

    def scanerrors(self, id, limit=None):
        return self._scan_service.scan_errors(id, limit)

    def scanlist(self):
        return self._scan_service.list_scans()

    def scanstatus(self, id):
        return self._scan_service.scan_status(id)

    def scansummary(self, id, by):
        return self._scan_service.scan_summary(id, by)

    def scancorrelations(self, id):
        return self._scan_service.scan_correlations(id)

    def scaneventresults(self, id, eventType=None, filterfp=False, correlationId=None):
        return self._scan_service.scan_event_results(id, eventType, filterfp, correlationId)

    def scaneventresultsunique(self, id, eventType, filterfp=False):
        return self._scan_service.scan_event_results_unique(id, eventType, filterfp)

    def search(self, id=None, eventType=None, value=None):
        try:
            return self.searchBase(id, eventType, value)
        except Exception:
            return []

    def scanhistory(self, id):
        if not id:
            return self.jsonify_error('404', "No scan specified")
        return self._scan_service.scan_history(id)

    def scanelementtypediscovery(self, id, eventType):
        return self._scan_service.scan_element_type_discovery(id, eventType)
