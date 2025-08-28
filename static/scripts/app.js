// CourierBuddy - Complete JavaScript Application Logic

// Global Variables
let currentUser = null;
let selectedTaskId = null;
let selectedRequestId = null;

// Application Data (simulating database for frontend-only functionality)
let appData = {
    users: {
        "user1": {
            "name": "John Smith",
            "email": "john@example.com",
            "password": "password123",
            "role": "user",
            "phone": "9876543210",
            "address": "123 Main St, City"
        },
        "admin1": {
            "name": "Admin User",
            "email": "admin@courierbuddy.com",
            "password": "admin123",
            "role": "admin",
            "phone": "9999999999",
            "address": "Admin Office"
        }
    },
    delivery_agents: {
        "agent1": {
            "name": "Mike Wilson",
            "email": "mike@example.com",
            "password": "agent123",
            "phone": "8765432109",
            "status": "available",
            "assigned_deliveries": []
        }
    },
    pickup_requests: {
        "req1": {
            "sender_id": "user1",
            "pickup_address": "123 Main St, City",
            "delivery_address": "456 Oak Ave, Town",
            "package_details": "Documents - Small envelope",
            "status": "pending",
            "assigned_agent": null,
            "created_at": "2025-08-20 10:00:00",
            "updated_at": "2025-08-20 10:00:00"
        }
    },
    status_options: ["pending", "assigned", "picked_up", "in_transit", "delivered", "cancelled"],
    notifications: []
};

// Utility Functions
function generateId(prefix) {
    return prefix + Math.random().toString(36).substr(2, 9);
}

function formatDate(dateString) {
    return new Date(dateString).toLocaleString();
}

function getCurrentDateTime() {
    return new Date().toISOString().replace('T', ' ').substring(0, 19);
}

// Toast Notification Functions
function showToast(message, type = 'success') {
    const toast = document.getElementById('toast');
    const messageEl = document.getElementById('toast-message');
    
    if (!toast || !messageEl) return;
    
    messageEl.textContent = message;
    toast.className = `toast show ${type}`;
    
    // Auto hide after 4 seconds
    setTimeout(() => {
        hideToast();
    }, 4000);
}

function hideToast() {
    const toast = document.getElementById('toast');
    if (toast) {
        toast.className = 'toast';
    }
}

// Authentication Functions
function handleLogin(event) {
    event.preventDefault();
    
    const email = document.getElementById('login-email').value;
    const password = document.getElementById('login-password').value;
    
    if (!email || !password) {
        showToast('Please fill in all fields', 'error');
        return;
    }
    
    // Show loading state
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = 'Logging in...';
    submitBtn.disabled = true;
    
    // Simulate API call with fetch to Flask backend
    fetch('/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            email: email,
            password: password
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast(data.message, 'success');
            setTimeout(() => {
                window.location.href = '/dashboard';
            }, 1000);
        } else {
            showToast(data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('Login failed. Please try again.', 'error');
    })
    .finally(() => {
        // Reset button state
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
    });
}

function handleSignup(event) {
    event.preventDefault();
    
    const formData = {
        name: document.getElementById('signup-name').value,
        email: document.getElementById('signup-email').value,
        phone: document.getElementById('signup-phone').value,
        address: document.getElementById('signup-address').value,
        password: document.getElementById('signup-password').value,
        role: document.getElementById('signup-role').value
    };
    
    // Basic validation
    for (let key in formData) {
        if (!formData[key]) {
            showToast('Please fill in all fields', 'error');
            return;
        }
    }
    
    if (formData.password.length < 6) {
        showToast('Password must be at least 6 characters long', 'error');
        return;
    }
    
    // Show loading state
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = 'Creating Account...';
    submitBtn.disabled = true;
    
    // Simulate API call with fetch to Flask backend
    fetch('/signup', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast(data.message, 'success');
            setTimeout(() => {
                window.location.href = '/login';
            }, 1500);
        } else {
            showToast(data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('Signup failed. Please try again.', 'error');
    })
    .finally(() => {
        // Reset button state
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
    });
}

function logout() {
    if (confirm('Are you sure you want to logout?')) {
        window.location.href = '/logout';
    }
}

// Pickup Scheduling Functions
function handleSchedulePickup(event) {
    event.preventDefault();
    
    const formData = {
        pickup_address: document.getElementById('pickup-address').value,
        delivery_address: document.getElementById('delivery-address').value,
        package_details: document.getElementById('package-details').value,
        estimated_delivery: document.getElementById('expected-delivery')?.value || ''
    };
    
    // Basic validation
    if (!formData.pickup_address || !formData.delivery_address || !formData.package_details) {
        showToast('Please fill in all required fields', 'error');
        return;
    }
    
    // Show loading state
    const submitBtn = event.target.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.innerHTML = '<span class="btn-icon">⏳</span> Scheduling...';
    submitBtn.disabled = true;
    
    // Submit to Flask backend
    fetch('/schedule_pickup', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(formData)
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast(data.message, 'success');
            setTimeout(() => {
                window.location.href = '/user_dashboard';
            }, 1500);
        } else {
            showToast(data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('Failed to schedule pickup. Please try again.', 'error');
    })
    .finally(() => {
        // Reset button state
        submitBtn.innerHTML = originalText;
        submitBtn.disabled = false;
    });
}

// Task Management Functions (for Couriers)
function openTaskModal(taskId) {
    selectedTaskId = taskId;
    const modal = document.getElementById('task-modal');
    if (!modal) return;
    
    modal.classList.remove('hidden');
    
    // Populate task details
    const detailsDiv = document.getElementById('task-details');
    if (detailsDiv) {
        detailsDiv.innerHTML = `
            <div class="task-info">
                <h4>Task ID: #${taskId}</h4>
                <p>Task details will be loaded here...</p>
            </div>
        `;
    }
}

function closeTaskModal() {
    const modal = document.getElementById('task-modal');
    if (modal) {
        modal.classList.add('hidden');
    }
    selectedTaskId = null;
}

function updateTaskStatus() {
    if (!selectedTaskId) return;
    
    const statusSelect = document.getElementById('status-update');
    if (!statusSelect) return;
    
    const newStatus = statusSelect.value;
    
    if (!newStatus) {
        showToast('Please select a status', 'error');
        return;
    }
    
    // Submit status update to Flask backend
    fetch('/api/update_status', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            request_id: selectedTaskId,
            status: newStatus
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast(data.message, 'success');
            closeTaskModal();
            setTimeout(() => {
                window.location.reload();
            }, 1000);
        } else {
            showToast(data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('Failed to update status. Please try again.', 'error');
    });
}

function assignRequest(requestId) {
    if (!requestId) return;
    
    if (!confirm('Are you sure you want to accept this delivery request?')) {
        return;
    }
    
    // Submit request assignment to Flask backend
    fetch('/api/assign_request', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            request_id: requestId
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast(data.message, 'success');
            setTimeout(() => {
                window.location.reload();
            }, 1000);
        } else {
            showToast(data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('Failed to assign request. Please try again.', 'error');
    });
}

// Admin Functions
function refreshStats() {
    showToast('Refreshing statistics...', 'info');
    
    fetch('/api/stats')
    .then(response => response.json())
    .then(data => {
        showToast('Statistics refreshed!', 'success');
        setTimeout(() => {
            window.location.reload();
        }, 1000);
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('Failed to refresh statistics', 'error');
    });
}

function viewUser(userId) {
    showToast(`Viewing user details for: ${userId}`, 'info');
    // Implement user details modal or navigation
}

function viewAgent(agentId) {
    showToast(`Viewing agent details for: ${agentId}`, 'info');
    // Implement agent details modal or navigation
}

function viewRequest(requestId) {
    window.location.href = `/track_delivery/${requestId}`;
}

function openAdminStatusModal(requestId) {
    selectedRequestId = requestId;
    const modal = document.getElementById('admin-status-modal');
    if (!modal) return;
    
    modal.classList.remove('hidden');
    
    // Populate request details
    const detailsDiv = document.getElementById('admin-request-details');
    if (detailsDiv) {
        detailsDiv.innerHTML = `
            <div class="request-info">
                <h4>Request ID: #${requestId}</h4>
                <p>Request details will be loaded here...</p>
            </div>
        `;
    }
}

function closeAdminStatusModal() {
    const modal = document.getElementById('admin-status-modal');
    if (modal) {
        modal.classList.add('hidden');
    }
    selectedRequestId = null;
}

function updateAdminStatus() {
    if (!selectedRequestId) return;
    
    const statusSelect = document.getElementById('admin-status-update');
    if (!statusSelect) return;
    
    const newStatus = statusSelect.value;
    
    if (!newStatus) {
        showToast('Please select a status', 'error');
        return;
    }
    
    // Submit status update to Flask backend
    fetch('/api/update_status', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify({
            request_id: selectedRequestId,
            status: newStatus
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showToast(data.message, 'success');
            closeAdminStatusModal();
            setTimeout(() => {
                window.location.reload();
            }, 1000);
        } else {
            showToast(data.message, 'error');
        }
    })
    .catch(error => {
        console.error('Error:', error);
        showToast('Failed to update status. Please try again.', 'error');
    });
}

// Support Functions
function showContactSupport() {
    const modal = document.getElementById('support-modal');
    if (modal) {
        modal.classList.remove('hidden');
    }
}

function closeSupportModal() {
    const modal = document.getElementById('support-modal');
    if (modal) {
        modal.classList.add('hidden');
    }
}

// Notification Functions
function loadNotifications() {
    fetch('/api/notifications')
    .then(response => response.json())
    .then(data => {
        if (data.notifications) {
            displayNotifications(data.notifications);
        }
    })
    .catch(error => {
        console.error('Error loading notifications:', error);
    });
}

function displayNotifications(notifications) {
    const container = document.getElementById('notifications-container');
    if (!container) return;
    
    container.innerHTML = '';
    
    if (notifications.length === 0) {
        container.innerHTML = '<p class="empty-notifications">No new notifications</p>';
        return;
    }
    
    notifications.forEach(notification => {
        const notificationEl = document.createElement('div');
        notificationEl.className = `notification-item notification-${notification.type}`;
        notificationEl.innerHTML = `
            <div class="notification-content">
                <p>${notification.message}</p>
                <small>${formatDate(notification.created_at)}</small>
            </div>
        `;
        container.appendChild(notificationEl);
    });
}

// Form Validation Functions
function validateEmail(email) {
    const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return re.test(email);
}

function validatePhone(phone) {
    const re = /^[0-9]{10}$/;
    return re.test(phone);
}

// Auto-fill today's date for pickup scheduling
function setMinDate() {
    const dateInput = document.getElementById('expected-delivery');
    if (dateInput) {
        const today = new Date().toISOString().split('T')[0];
        dateInput.min = today;
        dateInput.value = today;
    }
}

// Initialize functions when DOM loads
document.addEventListener('DOMContentLoaded', function() {
    // Set minimum date for delivery scheduling
    setMinDate();
    
    // Load notifications if on dashboard
    if (document.querySelector('.notifications-list')) {
        loadNotifications();
    }
    
    // Auto-refresh notifications every 30 seconds on dashboard pages
    if (window.location.pathname.includes('dashboard')) {
        setInterval(loadNotifications, 30000);
    }
    
    // Close modals when clicking outside
    document.addEventListener('click', function(event) {
        const modals = document.querySelectorAll('.modal');
        modals.forEach(modal => {
            if (event.target === modal) {
                modal.classList.add('hidden');
            }
        });
    });
    
    // Handle ESC key to close modals
    document.addEventListener('keydown', function(event) {
        if (event.key === 'Escape') {
            const modals = document.querySelectorAll('.modal:not(.hidden)');
            modals.forEach(modal => {
                modal.classList.add('hidden');
            });
        }
    });
    
    // Auto-hide toast notifications when clicked
    const toast = document.getElementById('toast');
    if (toast) {
        toast.addEventListener('click', hideToast);
    }
    
    // Form validation on submit
    const forms = document.querySelectorAll('form');
    forms.forEach(form => {
        form.addEventListener('submit', function(event) {
            const inputs = form.querySelectorAll('input[required], select[required], textarea[required]');
            let isValid = true;
            
            inputs.forEach(input => {
                if (!input.value.trim()) {
                    isValid = false;
                    input.classList.add('error');
                } else {
                    input.classList.remove('error');
                }
                
                // Email validation
                if (input.type === 'email' && input.value && !validateEmail(input.value)) {
                    isValid = false;
                    input.classList.add('error');
                    showToast('Please enter a valid email address', 'error');
                }
                
                // Phone validation
                if (input.type === 'tel' && input.value && !validatePhone(input.value)) {
                    isValid = false;
                    input.classList.add('error');
                    showToast('Please enter a valid 10-digit phone number', 'error');
                }
            });
            
            if (!isValid) {
                event.preventDefault();
                showToast('Please fill in all required fields correctly', 'error');
            }
        });
    });
    
    // Real-time form validation
    const inputs = document.querySelectorAll('input, select, textarea');
    inputs.forEach(input => {
        input.addEventListener('blur', function() {
            if (this.hasAttribute('required') && !this.value.trim()) {
                this.classList.add('error');
            } else {
                this.classList.remove('error');
            }
            
            // Email validation
            if (this.type === 'email' && this.value && !validateEmail(this.value)) {
                this.classList.add('error');
            }
            
            // Phone validation
            if (this.type === 'tel' && this.value && !validatePhone(this.value)) {
                this.classList.add('error');
            }
        });
        
        input.addEventListener('focus', function() {
            this.classList.remove('error');
        });
    });
});

// Legacy support for single-page application functions (if needed)
function showPage(pageId) {
    // This function is for backward compatibility with single-page app structure
    // In the Flask app, we use server-side routing instead
    console.log('Navigation to:', pageId);
}

// Utility function to handle page refreshes and navigation
function refreshPage() {
    window.location.reload();
}

function navigateBack() {
    window.history.back();
}

// Export functions for global access (if using modules)
window.CourierBuddy = {
    showToast,
    hideToast,
    handleLogin,
    handleSignup,
    handleSchedulePickup,
    openTaskModal,
    closeTaskModal,
    updateTaskStatus,
    assignRequest,
    refreshStats,
    viewUser,
    viewAgent,
    viewRequest,
    openAdminStatusModal,
    closeAdminStatusModal,
    updateAdminStatus,
    showContactSupport,
    closeSupportModal,
    logout,
    refreshPage,
    navigateBack
};

// Console welcome message
console.log('🚚 CourierBuddy Application Loaded Successfully!');
console.log('📦 Local courier scheduling and delivery tracking platform');
console.log('🔧 Built with Flask, HTML, CSS, and JavaScript');