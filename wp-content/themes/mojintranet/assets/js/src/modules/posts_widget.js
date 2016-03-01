(function($) {
  "use strict";

  var App = window.App;

  App.PostsWidget = function() {
    this.$top = $('.template-home .posts-widget');
    if(!this.$top.length) { return; }
    this.init();
  };

  App.PostsWidget.prototype = {
    init: function() {
      this.applicationUrl = $('head').data('application-url');
      this.templateUri = $('head').data('template-uri');
      this.serviceUrl = this.applicationUrl + '/service/post////1/5';
      this.pageBase = this.applicationUrl + '/' + this.$top.data('top-level-slug');
      this.genericThumbnailPath = this.templateUri + '/assets/images/blog-placeholder.jpg';

      this.itemTemplate = this.$top.find('[data-name="widget-post-item"]').html();

      this.resultsLoaded = true;
      this.serviceXHR = null;

      this.cacheEls();
      this.bindEvents();

      this.requestPosts();
    },

    cacheEls: function() {
      this.$postsList = this.$top.find('.posts-list');
    },

    bindEvents: function() {
      var _this = this;
    },

    requestPosts: function() {
      var _this = this;
      var dataArray = [];

      /* use the timeout for dev/debugging purposes */
      //**/window.setTimeout(function() {
        _this.serviceXHR = $.getJSON(_this.serviceUrl+'/'+dataArray.join('/'), $.proxy(_this.displayPosts, _this));
      //**/}, 2000);
    },

    displayPosts: function(data) {
      var _this = this;
      var $post;

      $.each(data.results, function(index, result) {
        $post = _this.buildResultRow(result);
        _this.$postsList.append($post);
      });

      this.resultsLoaded = true;
      this.$top.removeClass('loading');
    },

    buildResultRow: function(data) {
      var $child = $(this.itemTemplate);
      var date = App.tools.parseDate(data.timestamp);
      var author = data.authors[0];

      if(!data.thumbnail_url) {
        data.thumbnail_url = this.genericThumbnailPath;
        data.thumbnail_alt_text = 'generic blog thumbnail';
      }

      $child.find('.post-thumbnail').attr('src', author.thumbnail_url);
      $child.find('.post-title .post-link').attr('href', data.url);
      $child.find('.post-title .post-link').html(data.title);
      $child.find('.post-link, .post-link-thumbnail').attr('href', data.url);
      $child.find('.post-date').html(App.tools.formatDate(date, true));
      $child.find('.post-author').html(author.name);

      return $child;
    }
  };
}(jQuery));
