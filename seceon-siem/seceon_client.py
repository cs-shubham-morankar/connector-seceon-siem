"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

import requests
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger('seceon-siem')


class SeceonClient(object):
    """
    HTTP client for Seceon OTM REST API.
    """

    def __init__(self, config):
        self.base_url = config.get('serverURL', '').rstrip('/')
        self.token = config.get('aPIToken', '').strip()
        self.tenant_id = config.get('tenantID', '').strip()
        self.verify_ssl = config.get('verifySSL', True)

        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': 'Bearer {0}'.format(self.token),
        })

    def make_request(self, method, endpoint, params=None, data=None, tenant_id=None):
        """
        Central HTTP request method.
        Injects tenant_id as query param when available.
        """
        url = '{0}{1}'.format(self.base_url, endpoint)
        query_params = params or {}
        tid = (tenant_id or self.tenant_id or '').strip()
        if tid:
            query_params['tenant_id'] = tid

        logger.debug('{0} {1} params={2}'.format(method.upper(), url, query_params))

        try:
            response = self.session.request(
                method=method.upper(),
                url=url,
                params=query_params if query_params else None,
                json=data,
                verify=self.verify_ssl,
                timeout=30
            )
            return self._handle_response(response)

        except ConnectorError:
            raise
        except requests.exceptions.SSLError as err:
            logger.error('SSL Error: {0}'.format(str(err)))
            raise ConnectorError(
                'SSL certificate verification failed. '
                'Disable Verify SSL in connector configuration for '
                'self-signed certificates. Error: {0}'.format(str(err))
            )
        except requests.exceptions.ConnectionError as err:
            logger.error('Connection Error: {0}'.format(str(err)))
            raise ConnectorError(
                'Failed to connect to Seceon server at {0}. '
                'Verify the Server URL and network/VPN connectivity. '
                'Error: {0}'.format(self.base_url, str(err))
            )
        except requests.exceptions.Timeout:
            logger.error('Request timed out')
            raise ConnectorError(
                'Request timed out after 30 seconds. '
                'Check server availability and network latency.'
            )
        except Exception as err:
            logger.error('Unexpected error: {0}'.format(str(err)))
            raise ConnectorError(
                'Unexpected error during API call: {0}'.format(str(err))
            )

    def _handle_response(self, response):
        """
        Evaluate HTTP response.
        Returns parsed JSON on success, raises ConnectorError on failure.
        """
        logger.debug('Response Status: {0}'.format(response.status_code))

        if response.ok:
            try:
                return response.json()
            except ValueError:
                return {'status': 'Success', 'status_code': response.status_code}

        error_messages = {
            400: (
                'Bad Request (400) - Invalid search criteria or request body. '
                'Check the field names and values.'
            ),
            401: (
                'Unauthorized (401) - Bearer token is invalid or has been revoked. '
                'Re-generate the static auth key from the Seceon OTM portal and '
                'update the connector configuration.'
            ),
            403: (
                'Forbidden (403) - Token does not have permission for this operation. '
                'Check if a Global Auth Key requires tenant_id parameter.'
            ),
            404: (
                'Not Found (404) - The requested alert ID or resource does not exist.'
            ),
            405: (
                'Method Not Allowed (405) - Wrong HTTP method for this endpoint.'
            ),
            409: (
                'Conflict (409) - Resource conflict. '
                'The alert may already be in a closed state.'
            ),
            500: (
                'Internal Server Error (500) - An error occurred on the Seceon '
                'OTM platform. Contact your Seceon administrator.'
            ),
        }

        error_msg = error_messages.get(
            response.status_code,
            'HTTP Error {0}'.format(response.status_code)
        )

        try:
            body = response.json()
            if isinstance(body, dict):
                server_detail = (
                        body.get('message')
                        or body.get('error')
                        or str(body)
                )
                error_msg += ' | Server message: {0}'.format(server_detail)
        except Exception:
            if response.text:
                error_msg += ' | Response: {0}'.format(response.text[:300])

        logger.error(error_msg)
        raise ConnectorError(error_msg)

    def get(self, endpoint, params=None, tenant_id=None):
        return self.make_request('GET', endpoint, params=params, tenant_id=tenant_id)

    def post(self, endpoint, data, tenant_id=None):
        return self.make_request('POST', endpoint, data=data, tenant_id=tenant_id)

    def put(self, endpoint, data, tenant_id=None):
        return self.make_request('PUT', endpoint, data=data, tenant_id=tenant_id)

    def patch(self, endpoint, data, tenant_id=None):
        return self.make_request('PATCH', endpoint, data=data, tenant_id=tenant_id)

    def delete(self, endpoint, params=None, tenant_id=None):
        return self.make_request('DELETE', endpoint, params=params, tenant_id=tenant_id)


def get_client(config):
    return SeceonClient(config)
