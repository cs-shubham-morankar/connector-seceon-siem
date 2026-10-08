"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

from connectors.core.connector import get_logger, ConnectorError
from .seceon_client import get_client

logger = get_logger('seceon-siem')


def check_health(config):
    logger.info('Running Seceon SIEM connector health check')

    try:
        client = get_client(config)
        response = client.get('/api/v1/metadata/alertTypes')

        if not isinstance(response, list):
            raise ConnectorError(
                'Health check failed: Unexpected response from Seceon SIEM. '
                'Expected list of alert types but got: {0}'.format(type(response).__name__)
            )

        alert_type_count = len(response)
        logger.info(
            'Health check passed.'
            'Token is valid. Alert types available: {0}'.format(alert_type_count)
        )
        return True

    except ConnectorError:
        raise
    except Exception as err:
        logger.error('Unexpected error during health check: {0}'.format(str(err)))
        raise ConnectorError(
            'Connector health check failed with unexpected error: {0}'.format(str(err))
        )


def retrieve_alerts(config, params):
    logger.info('Executing retrieve_alerts')

    tenant_id = params.get('tenantID', '')
    scroll_id = (params.get('scrollID') or '').strip()

    # --- ScrollRequest takes priority over criteria ---
    if scroll_id:
        body = {'scroll_id': scroll_id}
        size = _safe_int(params.get('pageSize'), default=20, min_val=10, max_val=500)
        body['size'] = size
        logger.debug('retrieve_alerts: scroll request scroll_id={0}'.format(scroll_id[:10]))
    else:
        body = _build_alert_criteria(params)
        logger.debug('retrieve_alerts: criteria search body_keys={0}'.format(list(body.keys())))

    client = get_client(config)
    try:
        result = client.post('/api/v1/alert/search', body, tenant_id=tenant_id)
        record_count = len(result.get('response', []))
        logger.info('retrieve_alerts returned {0} alert(s)'.format(record_count))
        return result
    except ConnectorError:
        raise
    except Exception as err:
        raise ConnectorError('retrieve_alerts failed: {0}'.format(str(err)))


def _build_alert_criteria(params):
    body = {}

    alert_type = params.get('alertType')
    if alert_type:
        body['alert_type'] = alert_type

    alert_severity = params.get('alertSeverity')
    if alert_severity:
        body['alert_severity'] = alert_severity

    alert_status = params.get('alertStatus')
    if alert_status:
        body['alert_status'] = alert_status

    confidence_score = params.get('confidenceScoreRange')
    if confidence_score:
        if not isinstance(confidence_score, dict) or 'from' not in confidence_score:
            raise ConnectorError(
                'confidence_score must be a JSON object with at least a from key. '
                'Example: {"from": 50, "to": 75}'
            )
        body['confidence_score'] = confidence_score

    assigned_to = params.get('assignedTo')
    if assigned_to:
        body['assigned_to'] = _split_to_list(assigned_to)

    user_name = params.get('username')
    if user_name:
        body['user_name'] = _split_to_list(user_name)

    create_time = params.get('createTimeRange')
    if create_time:
        _validate_time_range(create_time, 'create_time')
        body['create_time'] = create_time

    update_time = params.get('updateTimeRange')
    if update_time:
        _validate_time_range(update_time, 'update_time')
        body['update_time'] = update_time

    size = params.get('pageSize')
    if size is not None:
        body['size'] = _safe_int(size, default=20, min_val=10, max_val=500)

    return body


def close_alert(config, params):
    logger.info('Executing close_alert')

    alert_id = params.get('alertID')
    tenant_id = params.get('tenantID', '')
    notes = params.get('closureNotes', '')
    performed_by = params.get('performedBy', '')
    is_enforced = params.get('isEnforced')

    body = {}
    if notes:
        body['notes'] = str(notes).strip()
    if performed_by:
        body['performed_by'] = str(performed_by).strip()
    if is_enforced is not None:
        body['is_enforced'] = bool(is_enforced)

    endpoint = '/api/v1/alert/{0}/close'.format(alert_id)
    client = get_client(config)
    try:
        result = client.patch(endpoint, body, tenant_id=tenant_id)
        logger.info('close_alert: alert {0} closed successfully'.format(alert_id))
        return result
    except ConnectorError:
        raise
    except Exception as err:
        raise ConnectorError(
            'close_alert failed for alert_id={0}: {1}'.format(alert_id, str(err))
        )


def search_threat_indicator_alert(config, params):
    logger.info('Executing search_threat_indicators')

    alert_id = params.get('alertID')
    tenant_override = (params.get('tenantID') or '').strip() or None
    scroll_id = (params.get('scrollID') or '').strip()

    if scroll_id:
        body = {'scroll_id': scroll_id}
        size = _safe_int(params.get('pageSize'), default=20, min_val=10, max_val=500)
        body['size'] = size
        logger.debug(
            'search_threat_indicators: scroll request for alert_id={0}'.format(alert_id)
        )
    else:
        body = _build_threat_indicator_criteria(params)
        logger.debug(
            'search_threat_indicators: criteria search for alert_id={0} '
            'body_keys={1}'.format(alert_id, list(body.keys()))
        )

    endpoint = '/api/v1/alert/{0}/threatIndicator/search'.format(alert_id)
    client = get_client(config)
    try:
        result = client.post(endpoint, body, tenant_id=tenant_override)
        record_count = len(result.get('response', []))
        logger.info(
            'search_threat_indicators: returned {0} indicator(s) '
            'for alert_id={1}'.format(record_count, alert_id)
        )
        return result
    except ConnectorError:
        raise
    except Exception as err:
        raise ConnectorError(
            'search_threat_indicators failed for alert_id={0}: {1}'.format(
                alert_id, str(err)
            )
        )


def _build_threat_indicator_criteria(params):
    body = {}

    src_ip = params.get('sourceIP', '')
    if src_ip:
        body['src_ip'] = _split_to_list(src_ip)

    dst_ip = params.get('destinationIP', '')
    if dst_ip:
        body['dst_ip'] = _split_to_list(dst_ip)

    event_origin = params.get('eventOrigin', '')
    if event_origin:
        values = _split_to_list(event_origin)
        body['event_origin'] = values

    event_type_name = params.get('eventTypeName', '')
    if event_type_name:
        body['event_type_name'] = _split_to_list(event_type_name)

    source_data_type = params.get('sourceDataType', '')
    if source_data_type:
        body['source_data_type'] = _split_to_list(source_data_type)

    user_name = params.get('userName', '')
    if user_name:
        body['user_name'] = _split_to_list(user_name)

    timestamp = params.get('timestampRange')
    if timestamp:
        _validate_time_range(timestamp, 'timestamp')
        body['timestamp'] = timestamp

    size = params.get('pageSize')
    if size is not None:
        body['size'] = _safe_int(size, default=20, min_val=10, max_val=500)

    return body


def execute_api_request(config, params):
    """Execute an arbitrary HTTP request against the Seceon OTM REST API."""
    logger.info('Executing execute_api_request')

    method = (params.get('method') or '').strip().upper()
    endpoint = (params.get('endpoint') or '').strip()
    query_params = params.get('queryParams')
    request_body = params.get('requestBody')
    tenant_id = (params.get('tenantID') or '').strip()

    if not endpoint.startswith('/'):
        raise ConnectorError(
            'Endpoint must be an absolute path beginning with "/". Got: "{0}"'.format(endpoint)
        )

    client = get_client(config)
    try:
        result = client.make_request(
            method=method,
            endpoint=endpoint,
            params=query_params or None,
            data=request_body,
            tenant_id=tenant_id,
        )
        logger.info(
            'execute_api_request {0} {1} completed successfully'.format(method, endpoint)
        )
        return result
    except ConnectorError:
        raise
    except Exception as err:
        raise ConnectorError(
            'execute_api_request failed for {0} {1}: {2}'.format(method, endpoint, str(err))
        )


def _safe_int(value, default, min_val, max_val):
    """Cast to int and clamp within [min_val, max_val]."""
    try:
        return max(min_val, min(max_val, int(value)))
    except (TypeError, ValueError):
        return default


def _validate_time_range(time_range, field_name):
    """Ensure time range is a dict with at least a from key."""
    if not isinstance(time_range, dict) or 'from' not in time_range:
        raise ConnectorError(
            '{0} must be a JSON object with at least a from key in ISO 8601 format. '
            'Example: {{"from": "2024-01-01T00:00:00.000Z", '
            '"to": "2024-01-31T23:59:59.000Z"}}'.format(field_name)
        )


def _split_to_list(value):
    """
    Convert a comma-separated string to a stripped list.
    Also handles values already provided as a list.
    Example: "10.10.10.1, 192.168.1.1" -> ["10.10.10.1", "192.168.1.1"]
    """
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    return [v.strip() for v in str(value).split(',') if v.strip()]
