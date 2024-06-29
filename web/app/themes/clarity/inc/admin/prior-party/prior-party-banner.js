/**
 * default data object
 */
jQuery(document).ready(function ($) {
    const JQ = {
        all: $('.ppb-posts'),
        rows: $('.ppb-posts__row'),
        header: $('.ppb-posts__row.header'),
        fixed: $('.header-fixed'),
        banners: {
            row: $('.ppb-banners__row')
        }
    };

    const MOJ_PPB = {
        on: {
            scroll: function (e) {
                const pbbPosts = JQ.all.offset().top - 32;
                const fixed  = JQ.fixed.append(JQ.header.clone());

                // init
                fixed.hide();
                $(window).bind("scroll", function () {
                    const offset = $(this).scrollTop();
                    const width = JQ.header.outerWidth();

                    if (offset >= pbbPosts && fixed.is(":hidden")) {
                        fixed.css({width: width + 'px'}).show();
                    } else if (offset < pbbPosts) {
                        fixed.hide();
                    }
                });
            },
            resize: function () {
                $(window).bind("resize", function () {
                    const width = JQ.header.outerWidth();

                    if (JQ.fixed.is(":visible")) {
                        JQ.fixed.css({width: width + 'px'})
                    }
                });
            }
        }
    }

    /**
     * React to clicks on banners, redirect to preview
     */
    JQ.banners.row.on('click', function (e) {
        // redirect to post preview...
        window.location.href = window.location.href + '&' +
            $.param({ 'ref': $(this).data('reference') })
    })

    /**
     * reconcile status
     */
    JQ.rows.find('.ppb-posts__status').each(function (key, element) {
        console.log('Data', {key: key, value: element})
        if ($(element).data('status') === 'on') {
            $(element).addClass('tick');
            return;
        }

        $(element).addClass('cross');
        $(element).parent().addClass('excluded');
    })

    /**
     * react to clicks on Post table, add the ID to the exclude array
     */
    JQ.rows.on('click', function (e) {
        const _this = $(this);
        const post_id = _this.data('id');
        const status  = _this.find('.ppb-posts__status');

        console.log(_this.attr('disabled'));
        if (_this.attr('disabled') === 'disabled') {
            return;
        }

        _this.attr('disabled', 'disabled');

        $.ajax({
            url: wpApiSettings.root + 'prior-party/v2/update',
            method: 'GET',
            beforeSend: function ( xhr ) {
                xhr.setRequestHeader('X-WP-Nonce', wpApiSettings.nonce);
            },
            data:{
                'status' : status.hasClass('tick') ? 'on' : 'off',
                'id': post_id
            }
        }).done(function ( response ) {
            response = JSON.parse(response);

            _this.attr('disabled', null);

            status.removeClass(response.message.old);
            status.addClass(response.message.new);

            if (response.message.new === 'tick') {
                _this.removeClass('excluded').attr('title', null);
                return true;
            }

            _this.addClass('excluded').attr('title', 'The banner will not be shown');
        });
    });

    JQ.rows.find('.nav-link').on('click', function (e) {
        e.stopPropagation();
    });

    MOJ_PPB.on.scroll();
    MOJ_PPB.on.resize();

});
