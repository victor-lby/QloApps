# QloApps API Reference

## Overview

QloApps provides a comprehensive RESTful API for hotel management operations. The API supports both XML and JSON formats and covers all major hotel operations including bookings, room management, availability checking, and system configuration.

## Authentication

### Web Service Key
All API requests require authentication using a web service key:
```
GET http://example.com/api/bookings?ws_key=YOUR_WS_KEY
```

### Basic Authentication
Alternative authentication using HTTP Basic Auth:
```
GET http://YOUR_WS_KEY@example.com/api/bookings
```

## Core API Resources

### Hotel ARI (Availability, Rates, Inventory)
**Endpoint**: `/api/hotel_ari`

The Hotel ARI API is the core resource for checking room availability, rates, and inventory.

#### Request Parameters
- `id_hotel` (required) - Hotel identifier
- `date_from` (required) - Start date (YYYY-MM-DD format)
- `date_to` (required) - End date (YYYY-MM-DD format)
- `id_room_type` (optional) - Specific room type filter
- `get_available_rooms` (boolean) - Include available rooms
- `get_booked_rooms` (boolean) - Include booked rooms
- `get_unavailable_rooms` (boolean) - Include unavailable rooms
- `get_partial_available_rooms` (boolean) - Include partially available rooms
- `date_wise_breakdown` (boolean) - Get day-by-day breakdown

#### Room Occupancy
```xml
<associations>
    <room_occupancies>
        <room_occupancy>
            <adults>2</adults>
            <children>0</children>
        </room_occupancy>
    </room_occupancies>
</associations>
```

#### Response Structure
```json
{
    "hotel_aris": [{
        "id_hotel": "1",
        "date_from": "2022-12-28",
        "date_to": "2022-12-29",
        "currency": "EUR",
        "total_rooms": 10,
        "total_available_rooms": 6,
        "total_unavailable_rooms": 2,
        "total_booked_rooms": 2,
        "room_types": [{
            "id_room_type": "1",
            "base_price": 1000,
            "base_price_with_tax": 1200,
            "total_price": 1000,
            "total_price_with_tax": 1200,
            "name": [{"id": "1", "value": "General Rooms"}],
            "rooms": {
                "available": [{"id_room": "2", "room_number": "A-102"}],
                "booked": [{"id_room": "1", "room_number": "A-101"}],
                "unavailable": [{"id_room": "4", "room_number": "A-104"}]
            }
        }]
    }]
}
```

### Bookings Management
**Endpoint**: `/api/bookings`

Complete booking lifecycle management including creation, updates, and retrieval.

#### Booking Structure
```json
{
    "booking": {
        "id": 1,
        "id_property": 1,
        "currency": "USD",
        "booking_status": "confirmed",
        "payment_status": "paid",
        "source": "qloapps.com",
        "booking_date": "2025-07-10 11:59:24",
        "associations": {
            "customer_detail": {
                "firstname": "John",
                "lastname": "Doe",
                "email": "guest@example.com",
                "phone": "1234567890"
            },
            "price_details": {
                "total_paid": 1125,
                "total_price_without_tax": 1000,
                "total_tax": 125
            },
            "room_types": [{
                "id_room_type": 1,
                "checkin_date": "2025-07-08 00:00:00",
                "checkout_date": "2025-07-09 00:00:00",
                "number_of_rooms": 1,
                "rooms": [{
                    "id_room": 1,
                    "adults": 1,
                    "child": 0,
                    "unit_price_without_tax": 900,
                    "services": [{
                        "id_service": 11,
                        "name": "Transport",
                        "quantity": 1,
                        "unit_price_without_tax": 100
                    }]
                }]
            }]
        }
    }
}
```

### Room Types Management
**Endpoint**: `/api/room_types`

Manage room type configurations, pricing, and multilingual content.

#### Multilingual Support
Room types support multiple languages for names and descriptions:

**Single Language Response**:
```json
{
    "room_type": {
        "id": 5,
        "name": "Delux Rooms",
        "description": "<p>King Size rooms for 2 adults and 2 children.</p>"
    }
}
```

**Multiple Languages Response**:
```json
{
    "room_type": {
        "id": 5,
        "name": [
            {"id": "1", "value": "Delux Rooms"},
            {"id": "2", "value": "Chambre de luxe"}
        ],
        "description": [
            {"id": "1", "value": "<p>King Size rooms for 2 adults and 2 children.</p>"},
            {"id": "2", "value": "<p>Chambres King Size pour 2 adultes et 2 enfants.</p>"}
        ]
    }
}
```

### Configuration Management
**Endpoint**: `/api/configurations`

System configuration management for settings and preferences.

#### Create/Update Configuration
```php
// Check if configuration exists
$xml = $webServiceObj->get([
    'resource' => 'configurations',
    'filter[name]' => '[PS_LANG_DEFAULT]',
]);

// Create or update
if (empty($xml->configurations->configuration)) {
    // Create new configuration
    $configXml = $webServiceObj->get(['url' => $url . 'api/configurations?schema=blank']);
    $configXml->configuration[0]->name = 'PS_LANG_DEFAULT';
    $configXml->configuration[0]->value = '3';
    
    $webServiceObj->add([
        'resource' => 'configurations',
        'postXml' => $configXml->asXML(),
    ]);
} else {
    // Update existing configuration
    $configurationId = (int) $xml->configurations->configuration[0]->attributes()['id'];
    $configXml = $webServiceObj->get(['resource' => 'configurations', 'id' => $configurationId]);
    $configXml->configuration[0]->value = '3';
    
    $webServiceObj->edit([
        'resource' => 'configurations',
        'id' => $configurationId,
        'putXml' => $configXml->asXML(),
    ]);
}
```

### Image Management
**Endpoint**: `/api/images/room_types/{id}`

Upload and manage room type images.

#### Upload Image (cURL)
```php
$imgUrl = 'http://example.com/api/images/room_types/10/';
$key = 'YOUR_WS_KEY';
$imgpath = '/path/to/image.jpg';

$params['image'] = new CurlFile($imgpath, 'image/jpg');

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $imgUrl);
curl_setopt($ch, CURLOPT_POST, 1);
curl_setopt($ch, CURLOPT_USERPWD, $key.':');
curl_setopt($ch, CURLOPT_POSTFIELDS, $params);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);

$result = curl_exec($ch);
$httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);
```

#### Update Image (HTML Form)
```html
<form action="http://WS_KEY@example.com/api/images/room_types/2" method="POST" enctype="multipart/form-data">
    <input name="ps_method" value="PUT" type="hidden">
    <input name="image" type="file">
    <input value="Submit" type="submit">
</form>
```

## API Usage Patterns

### Schema Discovery
Get API schema for any resource:
```
GET /api/bookings?ws_key=KEY&schema=blank
GET /api/bookings?ws_key=KEY&schema=synopsis
```

### Filtering and Pagination
```php
$opt = array(
    'resource' => 'states',
    'display' => 'full',
    'limit' => '9,5',  // Offset 9, limit 5
    'filter[name]' => '[California]'
);
```

### Output Format Control
```
GET /api/hotel_ari?ws_key=KEY&output_format=JSON
GET /api/hotel_ari?ws_key=KEY&output_format=XML
```

## Error Handling

### HTTP Status Codes
- `200` - Success
- `201` - Created
- `400` - Bad Request
- `401` - Unauthorized
- `404` - Not Found
- `500` - Internal Server Error

### Error Response Format
```json
{
    "errors": [{
        "code": 400,
        "message": "Invalid date format"
    }]
}
```

## Best Practices

### Performance Optimization
- Use specific filters to reduce response size
- Implement pagination for large datasets
- Cache frequently accessed data
- Use date_wise_breakdown only when necessary

### Security Guidelines
- Always use HTTPS in production
- Validate all input parameters
- Implement rate limiting
- Rotate web service keys regularly
- Sanitize file uploads

### Data Validation
- Validate date formats (YYYY-MM-DD)
- Check required fields before API calls
- Verify room occupancy limits
- Validate price and tax calculations

### Integration Patterns
- Use webhooks for real-time updates
- Implement retry logic for failed requests
- Handle partial failures gracefully
- Maintain data consistency across systems

## PHP WebService Library

QloApps provides a PHP library for easier API integration:

```php
require_once('./PSWebServiceLibrary.php');

$webService = new PrestaShopWebservice(
    'http://example.com/',
    'YOUR_WS_KEY',
    false // Debug mode
);

// Get resource
$xml = $webService->get(['resource' => 'bookings', 'id' => 1]);

// Create resource
$webService->add([
    'resource' => 'bookings',
    'postXml' => $xmlData->asXML()
]);

// Update resource
$webService->edit([
    'resource' => 'bookings',
    'id' => 1,
    'putXml' => $xmlData->asXML()
]);

// Delete resource
$webService->delete(['resource' => 'bookings', 'id' => 1]);
```

## Common Use Cases

### Check Room Availability
```xml
<qloapps>
    <hotel_ari>
        <id_hotel>1</id_hotel>
        <date_from>2024-12-28</date_from>
        <date_to>2024-12-30</date_to>
        <get_available_rooms>1</get_available_rooms>
        <associations>
            <room_occupancies>
                <room_occupancy>
                    <adults>2</adults>
                    <children>0</children>
                </room_occupancy>
            </room_occupancies>
        </associations>
    </hotel_ari>
</qloapps>
```

### Create Booking
```json
{
    "booking": {
        "id_property": 1,
        "currency": "USD",
        "booking_status": "confirmed",
        "payment_status": "pending",
        "associations": {
            "customer_detail": {
                "firstname": "John",
                "lastname": "Doe",
                "email": "john@example.com",
                "phone": "1234567890"
            },
            "room_types": [{
                "id_room_type": 1,
                "checkin_date": "2024-12-28 15:00:00",
                "checkout_date": "2024-12-30 11:00:00",
                "number_of_rooms": 1,
                "rooms": [{
                    "adults": 2,
                    "child": 0
                }]
            }]
        }
    }
}
```

### Update Room Pricing
```xml
<qloapps>
    <room_type>
        <id>5</id>
        <price>150.00</price>
        <name>
            <language id="1">Updated Room Name</language>
        </name>
    </room_type>
</qloapps>
```