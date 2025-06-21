// SecureSphere UI JavaScript
(function($) {
    'use strict';

    // Initialize when document is ready
    $(document).ready(function() {
        initWelcomeModal();
        initNavigation();
        initCharts();
        initLogs();
        initThemeSwitcher();
        initLoadingStates();
        initTooltips();
        initFlowcharts();
    });

    // Welcome Modal
    function initWelcomeModal() {
        const $modal = $(`
            <div class="ss-welcome-modal">
                <button class="ss-welcome-close">
                    <span class="dashicons dashicons-no-alt"></span>
                </button>
                <div class="ss-welcome-header">
                    <h1 class="ss-welcome-title">Welcome to SecureSpace</h1>
                    <p class="ss-welcome-subtitle">Owned by Trioxsec</p>
                    <p class="ss-welcome-subtitle">Made with ❤️ by Frenzy</p>
                </div>
            </div>
        `);

        // Show modal if not dismissed before
        if (!localStorage.getItem('securesphere-welcome-dismissed')) {
            $('body').append($modal);
        }

        // Handle close button
        $modal.find('.ss-welcome-close').on('click', function() {
            $modal.fadeOut(300, function() {
                $(this).remove();
            });
            localStorage.setItem('securesphere-welcome-dismissed', 'true');
        });
    }

    // Navigation handling
    function initNavigation() {
        const $navItems = $('.ss-nav-item');
        const currentPath = window.location.pathname;

        $navItems.each(function() {
            const $item = $(this);
            const href = $item.attr('href');
            
            if (currentPath.includes(href)) {
                $item.addClass('active');
            }
        });

        // Mobile navigation toggle
        $('.ss-nav-toggle').on('click', function() {
            $('.ss-nav').toggleClass('active');
        });
    }

    // Initialize charts
    function initCharts() {
        if (typeof Chart === 'undefined') return;

        // Attack Sources Chart
        const attackSourcesCtx = document.getElementById('attackSourcesChart');
        if (attackSourcesCtx) {
            const sources = JSON.parse(attackSourcesCtx.dataset.sources || '{}');
            new Chart(attackSourcesCtx, {
                type: 'doughnut',
                data: {
                    labels: Object.keys(sources),
                    datasets: [{
                        data: Object.values(sources),
                        backgroundColor: [
                            '#00ff9d',
                            '#00b8ff',
                            '#ff3d3d',
                            '#ffd700',
                            '#b3b3b3'
                        ],
                        borderWidth: 0
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: {
                        legend: {
                            position: 'right',
                            labels: {
                                color: '#ffffff',
                                font: {
                                    family: "'Inter', sans-serif"
                                }
                            }
                        }
                    },
                    animation: {
                        animateScale: true,
                        animateRotate: true
                    }
                }
            });
        }

        // Traffic Chart
        const trafficCtx = document.getElementById('trafficChart');
        if (trafficCtx) {
            const traffic = JSON.parse(trafficCtx.dataset.traffic || '[]');
            new Chart(trafficCtx, {
                type: 'line',
                data: {
                    labels: Array.from({length: 24}, (_, i) => `${i}:00`),
                    datasets: [{
                        label: 'Traffic',
                        data: traffic,
                        borderColor: '#00ff9d',
                        tension: 0.4,
                        fill: true,
                        backgroundColor: 'rgba(0, 255, 157, 0.1)'
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
                            beginAtZero: true,
                            grid: {
                                color: 'rgba(255, 255, 255, 0.1)'
                            },
                            ticks: {
                                color: '#ffffff',
                                font: {
                                    family: "'Inter', sans-serif"
                                }
                            }
                        },
                        x: {
                            grid: {
                                color: 'rgba(255, 255, 255, 0.1)'
                            },
                            ticks: {
                                color: '#ffffff',
                                font: {
                                    family: "'Inter', sans-serif"
                                }
                            }
                        }
                    },
                    animation: {
                        duration: 2000,
                        easing: 'easeInOutQuart'
                    }
                }
            });
        }
    }

    // Logs handling
    function initLogs() {
        const $logsContainer = $('.ss-logs');
        if (!$logsContainer.length) return;

        // Auto-scroll to bottom for new logs
        function scrollToBottom() {
            $logsContainer.scrollTop($logsContainer[0].scrollHeight);
        }

        // Initial scroll
        scrollToBottom();

        // Live log updates
        if (typeof EventSource !== 'undefined') {
            const eventSource = new EventSource('/wp-json/securesphere/v1/logs/stream');
            
            eventSource.onmessage = function(event) {
                const log = JSON.parse(event.data);
                appendLog(log);
                scrollToBottom();
            };

            eventSource.onerror = function() {
                eventSource.close();
            };
        }

        // Append new log entry
        function appendLog(log) {
            const $entry = $('<div>')
                .addClass('ss-log-entry ss-animate-fade-in')
                .html(`
                    <span class="ss-log-timestamp">${formatDate(log.timestamp)}</span>
                    <span class="ss-log-level ${log.level}">${log.level}</span>
                    <span class="ss-log-message">${log.message}</span>
                `);
            
            $logsContainer.append($entry);
        }

        // Log filtering
        $('.ss-log-filter').on('change', function() {
            const level = $(this).val();
            $('.ss-log-entry').show();
            
            if (level !== 'all') {
                $('.ss-log-entry').not(`.ss-log-level.${level}`).hide();
            }
        });
    }

    // Theme switcher
    function initThemeSwitcher() {
        const $themeToggle = $('.ss-theme-toggle');
        if (!$themeToggle.length) return;

        $themeToggle.on('click', function() {
            const $body = $('body');
            const isDark = $body.hasClass('ss-theme-dark');
            
            $body.toggleClass('ss-theme-dark ss-theme-light');
            localStorage.setItem('securesphere-theme', isDark ? 'light' : 'dark');
            
            // Update charts if they exist
            if (typeof Chart !== 'undefined') {
                Chart.instances.forEach(chart => chart.update());
            }
        });

        // Set initial theme
        const savedTheme = localStorage.getItem('securesphere-theme') || 'dark';
        $('body').addClass(`ss-theme-${savedTheme}`);
    }

    // Loading states
    function initLoadingStates() {
        // Add loading state to buttons
        $('.ss-button[data-loading]').on('click', function() {
            const $button = $(this);
            const originalText = $button.text();
            
            $button
                .prop('disabled', true)
                .html('<span class="ss-loading"></span> Loading...');
            
            // Reset after action completes
            setTimeout(() => {
                $button
                    .prop('disabled', false)
                    .text(originalText);
            }, 1000);
        });

        // Add loading state to forms
        $('.ss-form').on('submit', function() {
            const $form = $(this);
            const $submitButton = $form.find('button[type="submit"]');
            
            if ($submitButton.length) {
                $submitButton
                    .prop('disabled', true)
                    .html('<span class="ss-loading"></span> Processing...');
            }
        });
    }

    // Tooltips
    function initTooltips() {
        $('.ss-tooltip').each(function() {
            const $tooltip = $(this);
            const tooltipText = $tooltip.data('tooltip');
            
            if (tooltipText) {
                $tooltip.attr('title', tooltipText);
            }
        });
    }

    // Flowcharts
    function initFlowcharts() {
        $('.ss-flowchart').each(function() {
            const $flowchart = $(this);
            const steps = $flowchart.data('steps');
            
            if (steps) {
                steps.forEach((step, index) => {
                    const $step = $('<div>')
                        .addClass('ss-flow-step')
                        .html(`
                            <span class="dashicons dashicons-${step.icon}"></span>
                            <span class="ss-flow-text">${step.text}</span>
                        `);
                    
                    $flowchart.append($step);
                });
            }
        });
    }

    // Utility functions
    function formatDate(date) {
        return new Date(date).toLocaleString('en-US', {
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit'
        });
    }

    function formatNumber(num) {
        return new Intl.NumberFormat('en-US').format(num);
    }

    // Export utility functions
    window.SecureSphere = {
        formatDate,
        formatNumber
    };

})(jQuery); 