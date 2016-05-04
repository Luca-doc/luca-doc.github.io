(function($) {
  "use strict";

  var App = window.App;

  App.AboutUsIndex = function() {
    this.$top = $('.template-about-us .template-container');
    if(!this.$top.length) { return; }
    this.init();
  };

  App.AboutUsIndex.prototype = {
    init: function() {
      var agency = App.tools.helpers.agency.getForContent();
      this.applicationUrl = $('head').data('application-url');
      this.serviceUrl = this.applicationUrl + '/service/children/' + agency + '//116';
      //http://mojintranet/service/children/hq//1942/

      this.categoryItemTemplate = this.$top.find('[data-name="widget-guidance-item"]').html();
      this.childItemTemplate = this.$top.find('[data-name="widget-guidance-child-item"]').html();

      this.resultsLoaded = false;

      this.cacheEls();

      this.requestData();
    },

    cacheEls: function() {
      this.$largeCategoriesList = this.$top.find('.guidance-categories-list.large');
      this.$smallCategoriesList = this.$top.find('.guidance-categories-list.small');
    },

    requestData: function() {
      var _this = this;

      /* use the timeout for dev/debugging purposes */
      //**/window.setTimeout(function() {
        _this.serviceXHR = $.getJSON(_this.serviceUrl, $.proxy(_this.displayData, _this));
      //**/}, 2000);
    },

    displayData: function(data) {
      var _this = this;
      var children;
      var $category;
      var mostVisitedList = data.results.slice(0, 6);
      var allList = data.results;
      var childrenList;

      mostVisitedList = App.tools.sortByKey(mostVisitedList, 'title');
      allList = App.tools.sortByKey(allList, 'title');

      $.each(mostVisitedList, function(index, category) {
        $category = _this.buildCategoryItem(category);
        _this.$largeCategoriesList.append($category);
        childrenList = App.tools.sortByKey(category.children, 'title');

        $.each(childrenList, function(index, child) {

          $category.find('> .children-list').append(_this.buildChildItem(child));
        });
      });

      $.each(data.results, function(index, category) {
        _this.$smallCategoriesList.append(_this.buildCategoryItem(category));
      });

      this.resultsLoaded = true;
      this.$top.removeClass('loading');
    },

    buildCategoryItem: function(data) {
      var $category = $(this.categoryItemTemplate);

      $category.find('a')
        .attr('href', data.url)
        .html(data.title);

      return $category;
    },

    buildChildItem: function(data) {
      var $child = $(this.childItemTemplate);

      $child.find('a')
        .attr('href', data.url)
        .html(data.title);

      return $child;
    }
  };
}(jQuery));
