"""
Copyright start
MIT License
Copyright (c) 2026 Fortinet Inc
Copyright end
"""

from connectors.core.connector import Connector
from connectors.core.connector import get_logger, ConnectorError
from .operations import (
    retrieve_alerts,
    close_alert,
    search_threat_indicator_alert,
    execute_api_request,
    check_health
)

logger = get_logger('seceon-siem')


class SeceonConnector(Connector):

    def execute(self, config, operation, params, **kwargs):
        logger.info('execute() called with operation: {0}'.format(operation))
        try:
            operation_map = {
                'retrieve_alerts': retrieve_alerts,
                'close_alert': close_alert,
                'search_threat_indicator_alert': search_threat_indicator_alert,
                'execute_api_request': execute_api_request
            }
            if operation not in operation_map:
                logger.error('Unsupported operation: {0}'.format(operation))
                raise ConnectorError('Unsupported operation: {0}'.format(operation))

            result = operation_map[operation](config, params)
            logger.info('Operation {0} completed successfully'.format(operation))
            return result

        except ConnectorError:
            raise
        except Exception as err:
            logger.exception('Unhandled exception in execute(): {0}'.format(str(err)))
            raise ConnectorError(str(err))

    def check_health(self, config):
        logger.info('check_health() invoked')
        return check_health(config)
