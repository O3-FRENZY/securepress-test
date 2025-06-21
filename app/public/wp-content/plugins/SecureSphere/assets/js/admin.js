jQuery(document).ready(function($) {
    // Initialize charts if Chart.js is available
    if (typeof Chart !== 'undefined') {
        initializeCharts();
    }

    // Handle firewall toggle
    $('#firewall-toggle').on('change', function() {
        const enabled = $(this).is(':checked');
        $.post(ajaxurl, {
            action: 'securesphere_toggle_firewall',
            enabled: enabled,
            nonce: SecureSphereData.nonce
        }, function(response) {
            if (response.success) {
                location.reload();
            }
        });
    });

    // Handle IP unblock
    $('.ss-unblock-ip').on('click', function(e) {
        e.preventDefault();
        const ip = $(this).data('ip');
        if (confirm('Are you sure you want to unblock this IP?')) {
            $.post(ajaxurl, {
                action: 'securesphere_unblock_ip',
                ip: ip,
                nonce: SecureSphereData.nonce
            }, function(response) {
                if (response.success) {
                    location.reload();
                }
            });
        }
    });

    // Initialize tooltips
    $('[data-tooltip]').each(function() {
        const tooltip = $(this).attr('data-tooltip');
        $(this).attr('title', tooltip);
    });

    // Handle welcome modal
    function dismissWelcomeModal() {
        $.post(ajaxurl, {
            action: 'securesphere_dismiss_welcome',
            nonce: SecureSphereData.nonce
        }, function() {
            $('#securesphere-welcome-modal').fadeOut();
        });
    }

    // Initialize charts
    function initializeCharts() {
        // Attack Sources Chart
        const attackSourcesCanvas = document.getElementById('attackSourcesChart');
        if (attackSourcesCanvas) {
            const sourcesData = JSON.parse(attackSourcesCanvas.dataset.sources || '{}');
            new Chart(attackSourcesCanvas, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(sourcesData),
                    datasets: [{
                        data: Object.values(sourcesData),
                        backgroundColor: [
                            '#2271b1',
                            '#72aee6',
                            '#135e96',
                            '#0a4b78',
                            '#043959'
                        ]
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right'
                        }
                    }
                }
            });
        }

        // Traffic Chart
        const trafficCanvas = document.getElementById('trafficChart');
        if (trafficCanvas) {
            const trafficData = JSON.parse(trafficCanvas.dataset.traffic || '[]');
            new Chart(trafficCanvas, {
                type: 'line',
                data: {
                    labels: Array.from({length: 24}, (_, i) => i + ':00'),
                    datasets: [{
                        label: 'Requests',
                        data: trafficData,
                        borderColor: '#2271b1',
                        backgroundColor: 'rgba(34, 113, 177, 0.1)',
                        fill: true,
                        tension: 0.4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            display: false
                        }
                    },
                    scales: {
                        y: {
                            beginAtZero: true
                        }
                    }
                }
            });
        }
    }

    // Handle form submissions
    $('.ss-form').on('submit', function(e) {
        e.preventDefault();
        const form = $(this);
        const submitButton = form.find('button[type="submit"]');
        const originalText = submitButton.text();

        submitButton.prop('disabled', true).text('Saving...');

        $.post(ajaxurl, {
            action: form.data('action'),
            nonce: SecureSphereData.nonce,
            ...form.serializeArray().reduce((obj, item) => {
                obj[item.name] = item.value;
                return obj;
            }, {})
        }, function(response) {
            if (response.success) {
                showNotification('Settings saved successfully', 'success');
            } else {
                showNotification('Error saving settings', 'error');
            }
        }).always(function() {
            submitButton.prop('disabled', false).text(originalText);
        });
    });

    // Notification system
    function showNotification(message, type = 'info') {
        const notification = $('<div>', {
            class: `ss-notification ss-notification-${type}`,
            text: message
        });

        $('body').append(notification);
        setTimeout(() => {
            notification.fadeOut(() => notification.remove());
        }, 3000);
    }

    // Handle tab navigation
    $('.ss-nav-item').on('click', function(e) {
        e.preventDefault();
        const target = $(this).data('target');
        
        $('.ss-nav-item').removeClass('active');
        $(this).addClass('active');
        
        $('.ss-tab-content').hide();
        $(`#${target}`).show();
    });

    // Initialize first tab
    $('.ss-nav-item:first').click();
}); 