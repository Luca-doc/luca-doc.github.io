jQuery(function() {
  "use strict";

  var App = window.App;

  //early
  App.ins.breakpoint = new App.Breakpoint();

  //mid
  App.ins.mobileHeader = new App.MobileHeader();
  App.ins.stickyNews = new App.StickyNews();
  //App.ins.guidanceAndSupport = new App.GuidanceAndSupport();
  App.ins.guidanceAndSupportContent = new App.GuidanceAndSupportContent();
  App.ins.azIndex = new App.AZIndex();
  App.ins.emergencyMessage = new App.EmergencyMessage();
  App.ins.tableOfContents = new App.TableOfContents();
  App.ins.childrenPages = new App.ChildrenPages();
  App.ins.tabbedContent = new App.TabbedContent();
  App.ins.news = new App.News();
  App.ins.searchResults = new App.SearchResults();
  App.ins.floaters = new App.Floaters();
  App.ins.collapsibleBlock = new App.CollapsibleBlock();
  App.ins.departmentDropdown = new App.DepartmentDropdown();
  App.ins.feeds = new App.Feeds();
  App.ins.skipToContent = new App.SkipToContent();
  App.ins.pageFeedback = new App.PageFeedback();
  App.ins.navigation = new App.Navigation();

  //late
  App.ins.breakpoint.trigger();
});
