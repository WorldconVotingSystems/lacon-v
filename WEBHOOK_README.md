# RegFox Webhook Implementation

This implementation provides a secure webhook endpoint for receiving registration data from RegFox and automatically creating or updating user accounts.

## Features

- **Security**: HMAC-SHA256 signature verification for webhook authenticity
- **Logging**: Comprehensive logging to both JSON files and database
- **User Management**: Automatic user creation/update based on registration data
- **Event Handling**: Support for registration, subscription, and registrant update events
- **Admin Interface**: Django admin interface for viewing webhook logs and registration data

## Configuration

### 1. Webhook Secret

Set the webhook secret in your Django settings or environment variables:

```python
# In settings.py or via nomnom convention system
REGFOX_WEBHOOK_SECRET = 'your-webhook-secret-here'
```

### 2. Database Migration

Run Django migrations to create the required database tables:

```bash
python manage.py makemigrations lacon_v_app
python manage.py migrate
```

### 3. Regfox Configuration

Configure your webhook in the Regfox control panel:

- **URL**: `https://your-domain.com/regfox_webhook/`
- **Events**: Select the events you want to receive (registration, subscription, etc.)
- **Secret**: Use the same secret you configured in Django settings

## Webhook Events Supported

### Registration Event (`registration`)
- Creates new user accounts based on billing information
- Stores registration data including order numbers, customer IDs
- Updates existing users if they already exist

### Subscription Event (`subscription`)
- Processes recurring payment notifications
- Links subscription data to existing users

### Registrant Update Events (`registrant_edit`, `registrant_cancel`)
- Handles registration modifications and cancellations
- Updates existing registration data

## Data Models

### RegistrationData
Stores registration information linked to Django users:
- RegFox identifiers (order ID, customer ID, etc.)
- Registration status and timestamps
- Raw webhook data for reference

### WebhookLog
Comprehensive logging of all webhook events:
- Request headers and payloads
- Processing results and errors
- Timestamps for audit trail

## Security Features

- **HMAC Signature Verification**: Validates webhook authenticity using shared secret
- **CSRF Exemption**: Properly configured for external webhook calls
- **Error Handling**: Comprehensive error logging and graceful failure handling

## Debugging

### JSON Log Files
All webhook payloads are logged to JSON files in `/tmp/webconnex_webhooks/` for debugging:
- Format: `{timestamp}_{event_type}_{delivery_id}.json`
- Contains full webhook payload and metadata

### Database Logs
Check the Django admin interface under "Webhook Logs" to view:
- Processing status of each webhook
- Error messages for failed webhooks
- Full request/response data

### Admin Interface
Access the Django admin to view:
- **Registration Data**: User registration information from webhooks
- **Webhook Logs**: Complete audit trail of webhook processing

## Error Handling

The webhook implementation includes robust error handling:

1. **Invalid JSON**: Returns 400 Bad Request
2. **Invalid Signature**: Returns 400 Bad Request (if secret configured)
3. **Processing Errors**: Logged to database and JSON files
4. **Database Errors**: Gracefully handled with error logging

## Testing

To test the webhook locally:

1. Use a tool like ngrok to expose your local server
2. Configure the webhook URL in Regfox to point to your ngrok URL
3. Monitor the webhook logs in Django admin and JSON files
4. Verify user creation in Django admin

## Production Considerations

1. **Secret Management**: Store webhook secrets securely (environment variables)
2. **Log Rotation**: Monitor and rotate JSON log files to prevent disk space issues
3. **Database Monitoring**: Monitor webhook log table growth
4. **Error Alerts**: Set up monitoring for webhook processing failures
5. **Rate Limiting**: Consider implementing rate limiting if needed

## Customization

The webhook handlers include stub functions that can be extended:

- `_handle_registration_event()`: Customize user creation logic
- `_handle_subscription_event()`: Add subscription processing
- `_handle_registrant_update_event()`: Handle registration updates

Each handler returns a result dictionary that's logged for debugging and audit purposes.