# QloApps Hook System Proposals

## Overview

QloApps uses a hook-based architecture to allow modules to extend functionality at specific points in the application lifecycle. Here are proposed hooks specifically designed for hotel management operations.

## Booking Lifecycle Hooks

### Core Booking Hooks
```php
// Booking creation process
'actionBookingValidateData'     // Before booking data validation
'actionBookingCreate'           // After booking is created
'actionBookingCreateBefore'     // Before booking creation
'actionBookingCreateAfter'      // After successful booking creation

// Booking updates
'actionBookingUpdate'           // When booking is modified
'actionBookingUpdateBefore'     // Before booking update
'actionBookingUpdateAfter'      // After booking update
'actionBookingStatusChange'     // When booking status changes

// Booking cancellation
'actionBookingCancel'           // When booking is cancelled
'actionBookingCancelBefore'     // Before cancellation process
'actionBookingCancelAfter'      // After cancellation complete

// Booking confirmation
'actionBookingConfirm'          // When booking is confirmed
'actionBookingConfirmBefore'    // Before confirmation
'actionBookingConfirmAfter'     // After confirmation

// Check-in/Check-out process
'actionBookingCheckIn'          // Guest check-in process
'actionBookingCheckOut'         // Guest check-out process
'actionBookingNoShow'           // When guest doesn't show up
```

### Booking Display Hooks
```php
// Frontend booking display
'displayBookingForm'            // In booking form
'displayBookingFormTop'         // Top of booking form
'displayBookingFormBottom'      // Bottom of booking form
'displayBookingConfirmation'    // Booking confirmation page
'displayBookingDetails'         // Booking details view
'displayBookingHistory'         // Customer booking history

// Admin booking display
'displayAdminBookingList'       // Admin booking list
'displayAdminBookingForm'       // Admin booking form
'displayAdminBookingDetails'    // Admin booking details
'displayAdminBookingActions'    // Admin booking action buttons
```

## Room Management Hooks

### Room Availability Hooks
```php
// Room availability checking
'actionRoomAvailabilityCheck'   // When checking room availability
'actionRoomAvailabilityUpdate'  // When availability changes
'actionRoomStatusChange'        // When room status changes
'actionRoomBlock'               // When room is blocked
'actionRoomUnblock'             // When room is unblocked

// Room assignment
'actionRoomAssign'              // When room is assigned to booking
'actionRoomUnassign'            // When room assignment is removed
'actionRoomUpgrade'             // When guest is upgraded
'actionRoomDowngrade'           // When guest is downgraded
```

### Room Type Management Hooks
```php
// Room type operations
'actionRoomTypeCreate'          // New room type created
'actionRoomTypeUpdate'          // Room type updated
'actionRoomTypeDelete'          // Room type deleted
'actionRoomTypePriceUpdate'     // Room type price changed

// Room type display
'displayRoomTypeDetails'        // Room type details page
'displayRoomTypeList'           // Room type listing
'displayRoomTypeFeatures'       // Room features display
'displayRoomTypeImages'         // Room image gallery
'displayRoomTypeBookingForm'    // Room-specific booking form
```

## Pricing and Revenue Hooks

### Dynamic Pricing Hooks
```php
// Price calculation
'actionPriceCalculate'          // During price calculation
'actionPriceCalculateBefore'    // Before price calculation
'actionPriceCalculateAfter'     // After price calculation
'filterRoomPrice'               // Filter room base price
'filterTotalPrice'              // Filter total booking price

// Seasonal pricing
'actionSeasonalPriceApply'      // Apply seasonal pricing
'actionPromotionApply'          // Apply promotions/discounts
'actionTaxCalculate'            // Tax calculation
'actionCurrencyConvert'         // Currency conversion

// Revenue management
'actionRevenueUpdate'           // Revenue data update
'actionOccupancyUpdate'         // Occupancy rate update
'actionADRUpdate'               // Average Daily Rate update
```

## Guest and Customer Hooks

### Guest Management Hooks
```php
// Guest registration
'actionGuestRegister'           // Guest registration
'actionGuestUpdate'             // Guest profile update
'actionGuestPreferencesUpdate'  // Guest preferences update
'actionGuestLoyaltyUpdate'      // Loyalty program update

// Guest services
'actionGuestServiceRequest'     // Service request made
'actionGuestComplaint'          // Complaint filed
'actionGuestFeedback'           // Feedback submitted
'actionGuestCheckInComplete'    // Check-in completed
'actionGuestCheckOutComplete'   // Check-out completed

// Guest communication
'actionGuestNotification'       // Send notification to guest
'actionGuestEmailSend'          // Email sent to guest
'actionGuestSMSSend'            // SMS sent to guest
```

### Customer Account Hooks
```php
// Customer account management
'displayCustomerAccount'        // Customer account page
'displayCustomerBookings'       // Customer bookings list
'displayCustomerProfile'        // Customer profile page
'displayCustomerPreferences'    // Customer preferences
'displayCustomerLoyalty'        // Loyalty program display
```

## Payment and Financial Hooks

### Payment Processing Hooks
```php
// Payment lifecycle
'actionPaymentProcess'          // Payment processing
'actionPaymentProcessBefore'    // Before payment processing
'actionPaymentProcessAfter'     // After payment processing
'actionPaymentSuccess'          // Successful payment
'actionPaymentFailed'           // Failed payment
'actionPaymentRefund'           // Payment refund
'actionPaymentPartial'          // Partial payment

// Payment methods
'displayPaymentMethods'         // Available payment methods
'displayPaymentForm'            // Payment form
'displayPaymentReturn'          // Payment return page
'displayPaymentConfirmation'    // Payment confirmation
```

### Financial Reporting Hooks
```php
// Financial operations
'actionInvoiceGenerate'         // Invoice generation
'actionReceiptGenerate'         // Receipt generation
'actionFinancialReportUpdate'   // Financial report update
'actionRevenueRecognition'      // Revenue recognition
```

## Hotel Operations Hooks

### Housekeeping Hooks
```php
// Housekeeping operations
'actionHousekeepingAssign'      // Assign housekeeping task
'actionHousekeepingComplete'    // Housekeeping task completed
'actionRoomCleaningStart'       // Room cleaning started
'actionRoomCleaningComplete'    // Room cleaning completed
'actionRoomInspection'          // Room inspection
'actionMaintenanceRequest'      // Maintenance request
'actionMaintenanceComplete'     // Maintenance completed

// Room status updates
'actionRoomStatusDirty'         // Room marked as dirty
'actionRoomStatusClean'         // Room marked as clean
'actionRoomStatusOutOfOrder'    // Room out of order
'actionRoomStatusInService'     // Room back in service
```

### Inventory Management Hooks
```php
// Inventory operations
'actionInventoryUpdate'         // Inventory level update
'actionInventoryLowStock'       // Low stock alert
'actionInventoryReorder'        // Reorder trigger
'actionInventoryReceive'        // Inventory received
'actionInventoryConsume'        // Inventory consumed
```

## Channel Management Hooks

### Distribution Channel Hooks
```php
// Channel management
'actionChannelSync'             // Sync with booking channels
'actionChannelRateUpdate'       // Update rates on channels
'actionChannelAvailabilityUpdate' // Update availability on channels
'actionChannelBookingReceive'   // Booking received from channel
'actionChannelBookingSync'      // Sync booking with channel

// OTA integration
'actionOTAConnect'              // Connect to OTA
'actionOTADisconnect'           // Disconnect from OTA
'actionOTABookingImport'        // Import OTA booking
'actionOTABookingExport'        // Export booking to OTA
```

## Reporting and Analytics Hooks

### Analytics Hooks
```php
// Analytics and reporting
'actionAnalyticsUpdate'         // Analytics data update
'actionReportGenerate'          // Report generation
'actionKPICalculate'            // KPI calculation
'actionDashboardUpdate'         // Dashboard data update
'actionPerformanceMetrics'      // Performance metrics update

// Business intelligence
'actionOccupancyAnalysis'       // Occupancy analysis
'actionRevenueAnalysis'         // Revenue analysis
'actionGuestAnalysis'           // Guest behavior analysis
'actionMarketAnalysis'          // Market analysis
```

## Communication and Notification Hooks

### Notification System Hooks
```php
// Email notifications
'actionEmailBookingConfirmation'    // Booking confirmation email
'actionEmailBookingReminder'        // Booking reminder email
'actionEmailCheckInReminder'        // Check-in reminder
'actionEmailCheckOutReminder'       // Check-out reminder
'actionEmailCancellation'           // Cancellation email
'actionEmailPromotion'              // Promotional email

// SMS notifications
'actionSMSBookingConfirmation'      // Booking confirmation SMS
'actionSMSCheckInReminder'          // Check-in reminder SMS
'actionSMSCheckOutReminder'         // Check-out reminder SMS

// Push notifications
'actionPushNotification'            // Push notification
'actionInAppNotification'           // In-app notification
```

## Admin and Management Hooks

### Admin Interface Hooks
```php
// Admin dashboard
'displayAdminDashboard'         // Admin dashboard
'displayAdminDashboardTop'      // Top of admin dashboard
'displayAdminDashboardBottom'   // Bottom of admin dashboard
'displayAdminStats'             // Admin statistics
'displayAdminAlerts'            // Admin alerts

// Admin forms
'displayAdminFormTop'           // Top of admin forms
'displayAdminFormBottom'        // Bottom of admin forms
'displayAdminListTop'           // Top of admin lists
'displayAdminListBottom'        // Bottom of admin lists

// Admin actions
'actionAdminLogin'              // Admin login
'actionAdminLogout'             // Admin logout
'actionAdminPermissionCheck'    // Permission check
'actionAdminAuditLog'           // Audit log entry
```

## Security and Compliance Hooks

### Security Hooks
```php
// Security operations
'actionSecurityCheck'           // Security check
'actionLoginAttempt'            // Login attempt
'actionLoginSuccess'            // Successful login
'actionLoginFailed'             // Failed login
'actionPasswordChange'          // Password change
'actionDataAccess'              // Data access logging
'actionDataModification'        // Data modification logging

// Compliance
'actionGDPRDataRequest'         // GDPR data request
'actionGDPRDataExport'          // GDPR data export
'actionGDPRDataDelete'          // GDPR data deletion
'actionComplianceAudit'         // Compliance audit
```

## Integration and API Hooks

### API Hooks
```php
// API operations
'actionAPIRequest'              // API request received
'actionAPIResponse'             // API response sent
'actionAPIAuthentication'       // API authentication
'actionAPIRateLimit'            // API rate limiting
'actionAPIError'                // API error occurred

// Webhook operations
'actionWebhookSend'             // Send webhook
'actionWebhookReceive'          // Receive webhook
'actionWebhookProcess'          // Process webhook data
```

## Implementation Examples

### Booking Creation Hook Implementation
```php
// In module installation
public function install()
{
    return parent::install() &&
        $this->registerHook('actionBookingCreateBefore') &&
        $this->registerHook('actionBookingCreateAfter');
}

// Hook implementation
public function hookActionBookingCreateBefore($params)
{
    $booking_data = $params['booking_data'];
    
    // Validate special requirements
    if (!$this->validateSpecialRequests($booking_data)) {
        throw new Exception('Invalid special requests');
    }
    
    // Check room availability one more time
    if (!$this->verifyRoomAvailability($booking_data)) {
        throw new Exception('Room no longer available');
    }
    
    // Apply dynamic pricing
    $booking_data['total_price'] = $this->calculateDynamicPrice($booking_data);
    
    return $booking_data;
}

public function hookActionBookingCreateAfter($params)
{
    $booking = $params['booking'];
    
    // Send confirmation email
    $this->sendBookingConfirmation($booking);
    
    // Update channel manager
    $this->updateChannelAvailability($booking);
    
    // Log booking for analytics
    $this->logBookingAnalytics($booking);
    
    // Trigger housekeeping preparation
    $this->scheduleHousekeeping($booking);
}
```

### Room Status Hook Implementation
```php
public function hookActionRoomStatusChange($params)
{
    $room = $params['room'];
    $old_status = $params['old_status'];
    $new_status = $params['new_status'];
    
    switch ($new_status) {
        case 'dirty':
            $this->scheduleHousekeeping($room);
            break;
        case 'clean':
            $this->updateRoomAvailability($room, true);
            $this->notifyFrontDesk($room, 'ready');
            break;
        case 'out_of_order':
            $this->updateRoomAvailability($room, false);
            $this->notifyMaintenance($room);
            break;
        case 'maintenance':
            $this->blockRoomBookings($room);
            break;
    }
    
    // Update channel manager
    $this->syncRoomStatus($room, $new_status);
}
```

### Dynamic Pricing Hook Implementation
```php
public function hookFilterRoomPrice($params)
{
    $base_price = $params['price'];
    $room_type = $params['room_type'];
    $dates = $params['dates'];
    $occupancy = $params['occupancy'];
    
    // Apply seasonal adjustments
    $seasonal_multiplier = $this->getSeasonalMultiplier($dates);
    $adjusted_price = $base_price * $seasonal_multiplier;
    
    // Apply demand-based pricing
    $demand_multiplier = $this->getDemandMultiplier($room_type, $dates);
    $adjusted_price *= $demand_multiplier;
    
    // Apply occupancy-based pricing
    $occupancy_multiplier = $this->getOccupancyMultiplier($occupancy);
    $adjusted_price *= $occupancy_multiplier;
    
    // Apply minimum/maximum price limits
    $adjusted_price = $this->applyPriceLimits($adjusted_price, $room_type);
    
    return $adjusted_price;
}
```

## Hook Registration Best Practices

### Module Hook Registration
```php
public function install()
{
    $hooks = array(
        // Core booking hooks
        'actionBookingCreateBefore',
        'actionBookingCreateAfter',
        'actionBookingUpdate',
        'actionBookingCancel',
        
        // Display hooks
        'displayBookingForm',
        'displayRoomDetails',
        
        // Admin hooks
        'displayAdminBookingList',
        'actionAdminBookingUpdate'
    );
    
    $success = parent::install();
    
    foreach ($hooks as $hook) {
        $success = $success && $this->registerHook($hook);
    }
    
    return $success;
}
```

### Hook Parameter Standards
```php
// Standard hook parameters structure
$hook_params = array(
    'booking' => $booking_object,           // Main object
    'customer' => $customer_object,         // Related customer
    'room' => $room_object,                 // Related room
    'hotel' => $hotel_object,               // Related hotel
    'context' => $this->context,            // Application context
    'additional_data' => $extra_data        // Hook-specific data
);

Hook::exec('actionBookingCreate', $hook_params);
```

These hooks provide comprehensive extension points for QloApps hotel management functionality, enabling modules to integrate seamlessly with the booking lifecycle, room management, guest services, and business operations.