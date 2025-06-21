jQuery(document).ready(function($) {
    // Handle country clicks
    $('.country').on('click', function() {
        const countryCode = $(this).data('country');
        const isBlocked = $(this).hasClass('blocked');
        
        // Toggle blocked class
        $(this).toggleClass('blocked');
        
        // Send AJAX request to update blocking status
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'securesphere_toggle_country_block',
                country: countryCode,
                blocked: !isBlocked,
                nonce: securesphereMap.nonce
            },
            success: function(response) {
                if (response.success) {
                    // Show success message
                    const message = isBlocked ? 
                        'Country has been unblocked.' : 
                        'Country has been blocked.';
                    
                    const notice = $('<div class="notice notice-success is-dismissible"><p>' + message + '</p></div>');
                    $('.wrap h1').after(notice);
                    
                    // Auto-dismiss after 3 seconds
                    setTimeout(function() {
                        notice.fadeOut(function() {
                            $(this).remove();
                        });
                    }, 3000);
                } else {
                    // Show error message
                    const notice = $('<div class="notice notice-error is-dismissible"><p>Error updating country status.</p></div>');
                    $('.wrap h1').after(notice);
                    
                    // Revert the toggle if there was an error
                    $(this).toggleClass('blocked');
                }
            },
            error: function() {
                // Show error message
                const notice = $('<div class="notice notice-error is-dismissible"><p>Error updating country status.</p></div>');
                $('.wrap h1').after(notice);
                
                // Revert the toggle if there was an error
                $(this).toggleClass('blocked');
            }
        });
    });

    // Handle continent blocking
    $('.block-continent').on('click', function() {
        const continent = $(this).data('continent');
        const countries = $('.country[data-continent="' + continent + '"]');
        
        countries.addClass('blocked');
        
        // Send AJAX request to block all countries in continent
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'securesphere_block_continent',
                continent: continent,
                nonce: securesphereMap.nonce
            },
            success: function(response) {
                if (response.success) {
                    const notice = $('<div class="notice notice-success is-dismissible"><p>All countries in ' + continent + ' have been blocked.</p></div>');
                    $('.wrap h1').after(notice);
                    
                    setTimeout(function() {
                        notice.fadeOut(function() {
                            $(this).remove();
                        });
                    }, 3000);
                } else {
                    const notice = $('<div class="notice notice-error is-dismissible"><p>Error blocking continent.</p></div>');
                    $('.wrap h1').after(notice);
                    countries.removeClass('blocked');
                }
            },
            error: function() {
                const notice = $('<div class="notice notice-error is-dismissible"><p>Error blocking continent.</p></div>');
                $('.wrap h1').after(notice);
                countries.removeClass('blocked');
            }
        });
    });

    // Handle continent unblocking
    $('.unblock-continent').on('click', function() {
        const continent = $(this).data('continent');
        const countries = $('.country[data-continent="' + continent + '"]');
        
        countries.removeClass('blocked');
        
        // Send AJAX request to unblock all countries in continent
        $.ajax({
            url: ajaxurl,
            type: 'POST',
            data: {
                action: 'securesphere_unblock_continent',
                continent: continent,
                nonce: securesphereMap.nonce
            },
            success: function(response) {
                if (response.success) {
                    const notice = $('<div class="notice notice-success is-dismissible"><p>All countries in ' + continent + ' have been unblocked.</p></div>');
                    $('.wrap h1').after(notice);
                    
                    setTimeout(function() {
                        notice.fadeOut(function() {
                            $(this).remove();
                        });
                    }, 3000);
                } else {
                    const notice = $('<div class="notice notice-error is-dismissible"><p>Error unblocking continent.</p></div>');
                    $('.wrap h1').after(notice);
                    countries.addClass('blocked');
                }
            },
            error: function() {
                const notice = $('<div class="notice notice-error is-dismissible"><p>Error unblocking continent.</p></div>');
                $('.wrap h1').after(notice);
                countries.addClass('blocked');
            }
        });
    });

    // Tab switching
    $(".nav-tab").on("click", function(e) {
        e.preventDefault();
        var target = $(this).data("tab");
        $(".nav-tab").removeClass("nav-tab-active");
        $(this).addClass("nav-tab-active");
        $(".tab-content").hide();
        $("#" + target).show();
    });
}); 