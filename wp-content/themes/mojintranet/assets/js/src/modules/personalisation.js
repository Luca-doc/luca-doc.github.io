(function($) {
  "use strict";

  var App = window.App;

  App.Personalisation = function() {
    this.init();
  };

  App.Personalisation.prototype = {
    init: function() {
      this.settings = {
        hideForAgency: {
          'hmcts': ['.events-widget', '.events-menu-item']
        }
      };

      this.agency = window.App.tools.helpers.agency.get();


      this.cacheEls();
      this.bindEvents();

      this.update();
      this.hideContent();
    },

    cacheEls: function() {
      this.$siteHeader = $('body > .header');
    },

    bindEvents: function() {
    },

    update: function() {
      var $homepage = $('.template-home');
      var name;

      $('html').attr('data-agency', this.agency);

      if($homepage.length) {
        $('.template-home h1').text(name);
      }
    },

    hideContent: function() {
      var selectorsToHide = this.settings.hideForAgency[this.agency] || [];

      $.each(selectorsToHide, function(index, selector) {
        $(selector).addClass('agency-hidden');
      });
    }
  };
}(window.jQuery));
