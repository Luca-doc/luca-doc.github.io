(function($) {
  "use strict";

  var App = window.App;

  App.DepartmentDropdown = function() {
    this.$myIntranetForm = $('.my-intranet-form');
    if(!this.$myIntranetForm.length) { return; }
    this.init();
  };

  App.DepartmentDropdown.prototype = {
    init: function() {
      this.settings = {
        cookieName: 'department_dropdown'
      };

      this.cacheEls();
      this.bindEvents();
      this.initDropdown();
    },

    cacheEls: function() {
      this.$departmentList = this.$myIntranetForm.find('.department-list');
      this.$departmentTrigger = this.$myIntranetForm.find('.department-dropdown-trigger');
      this.$departmentLabel = this.$departmentTrigger.find('.label');

      this.$agencyLinkList = $('.my-moj .agency-link-list');
      this.$agencyLinkItem = this.$agencyLinkList.find('.agency');
      this.$agencyLinkLabel = this.$agencyLinkList.find('.label');
    },

    bindEvents: function() {
      $(document).on('click', $.proxy(this.outsideClickHandle, this));
      this.$departmentTrigger.on('click', $.proxy(this.triggerClick, this));
      this.$departmentList.find('a').on('click', $.proxy(this.itemClick, this));
    },

    outsideClickHandle: function(e) {
      if(!$(e.target).closest(this.$myIntranetForm).length) {
        this.toggleList(false);
      }
    },

    initDropdown: function() {
      var department = this.readState();
      var text;
      var $defaultItem = this.$departmentList.find('li[data-default="1"]');

      if(!department) {
        department = $defaultItem.attr('data-department');
        text = $defaultItem.text();
      }
      else {
        text = this.$departmentList.find('li[data-department="' + department + '"]').text();
      }

      this.updateLabels(text, department);
      this.$agencyLinkList.removeClass('hidden');
    },

    triggerClick: function(e) {
      e.preventDefault();
      this.toggleList();
    },

    toggleList: function(toggle) {
      this.$departmentList.toggleClass('visible', toggle);
    },

    itemClick: function(e) {
      var $item = $(e.target);
      var department = $item.closest('li').data('department');
      var text = $item.text();

      e.preventDefault();

      this.$departmentList.removeClass('visible');
      this.updateLabels(text, department);

      this.saveState();
    },

    updateLabels: function(text, department) {
      this.$departmentLabel.html(text);
      this.$agencyLinkLabel.html(text);
      console.log(department);
      this.$departmentList.attr('data-department', department);
      this.$agencyLinkItem.attr('data-department', department);
    },

    saveState: function(e) {
      var department = this.$departmentList.attr('data-department');
      App.tools.setCookie(this.settings.cookieName, department, 3650);
    },

    readState: function() {
      return App.tools.getCookie(this.settings.cookieName);
    }
  };
}(window.jQuery));
