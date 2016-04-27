(function($) {
  "use strict";

  var App = window.App;

  App.tools.helpers = {
    agency: {
      integratedAgencies: ['hmcts', 'laa', 'opg'],

      get: function() {
        var agency = App.tools.getCookie('department_dropdown');

        return agency;
      },

      getForContent: function() {
        return this.isIntegrated() ? this.get() : 'hq';
      },

      isIntegrated: function() {
        var agency = this.get();

        return this.integratedAgencies.indexOf(agency) >= 0;
      }
    }
  };
}(jQuery));
