(function(){var t,e=function(t,e){return function(){return t.apply(e,arguments)}};t=function(){function t(t){this.updateTimestamps=e(this.updateTimestamps,this),this.postAutosaveCallback=e(this.postAutosaveCallback,this),this.overrideLock=e(this.overrideLock,this),this.restoreRevision=e(this.restoreRevision,this),this.enableSubmit=e(this.enableSubmit,this),this.autosaveEnableButtons=e(this.autosaveEnableButtons,this),this.hijackAutosave=e(this.hijackAutosave,this),this.$=t,this.$("#edit-desktop-button").click(this.editDocument),this.$(".revision").click(this.restoreRevision),this.$("#override_link").click(this.overrideLock),this.$("#document a").click(this.requestPermission),this.$(document).bind("autosaveComplete",this.postAutosaveCallback),this.$(document).bind("documentUpload",this.legacyPostDocumentUpload),this.$(":button, :submit","#submitpost").prop("disabled",!0),this.$("#misc-publishing-actions a").click(this.enableSubmit),this.$("input, select").on("change",this.enableSubmit),this.$("input[type=text], textarea").on("keyup",this.enableSubmit),this.bindPostDocumentUploadCB(),this.hijackAutosave(),setInterval(this.updateTimestamps,6e4)}return t.prototype.hasUpload=!1,t.prototype.window=window.dialogArguments||opener||parent||top,t.prototype.hijackAutosave=function(){return this.autosaveEnableButtonsOriginal=window.autosave_enable_buttons,window.autosave_enable_buttons=this.autosaveEnableButtons},t.prototype.autosaveEnableButtons=function(){return this.$(document).trigger("autosaveComplete"),this.hasUpload?this.autosaveEnableButtonsOriginal():void 0},t.prototype.enableSubmit=function(){return this.$(":button, :submit","#submitpost").removeAttr("disabled")},t.prototype.restoreRevision=function(t){return t.preventDefault(),confirm(wp_document_revisions.restoreConfirmation)?window.location.href=this.$(t.target).attr("href"):void 0},t.prototype.overrideLock=function(){return this.$.post(ajaxurl,{action:"override_lock",post_id:this.$("#post_ID").val()||0},function(t){return t?(this.$("#lock_override").hide(),this.$(".error").not("#lock-notice").hide(),this.$("#publish, .add_media, #lock-notice").fadeIn(),autosave()):alert(wp_document_revisions.lockError)})},t.prototype.requestPermission=function(){return null!=window.webkitNotifications?window.webkitNotifications.requestPermission():void 0},t.prototype.lockOverrideNotice=function(t){return window.webkitNotifications.checkPermission()>0?window.webkitNotifications.RequestPermission(lock_override_notice):window.webkitNotifications.createNotification(wp_document_revisions.lostLockNoticeLogo,wp_document_revisions.lostLockNoticeTitle,t).show()},t.prototype.postAutosaveCallback=function(){return this.$("#autosave-alert").length>0&&this.$("#lock-notice").length>0&&this.$("#lock-notice").is(":visible")?(wp_document_revisions.lostLockNotice=wp_document_revisions.lostLockNotice.replace("%s",this.$("#title").val()),window.webkitNotifications?lock_override_notice(wp_document_revisions.lostLockNotice):alert(wp_document_revisions.lostLockNotice),location.reload(!0)):void 0},t.prototype.legacyPostDocumentUpload=function(t,e){return this.postDocumentUpload(t,e)},t.prototype.human_time_diff=function(t,e){var o,i,n,s,r;return o=new Date,e=e||o.getTime()/1e3+parseInt(wp_document_revisions.offset),n=Math.abs(e-t),3600>=n?(r=Math.floor(n/60),r=this.roundUp(r),1===r?wp_document_revisions.minute.replace("%d",r):wp_document_revisions.minutes.replace("%d",r)):86400>=n&&n>3600?(s=Math.floor(n/3600),s=this.roundUp(s),1===s?wp_document_revisions.hour.replace("%d",s):wp_document_revisions.hours.replace("%d",s)):n>=86400?(i=Math.floor(n/86400),i=this.roundUp(i),1===i?wp_document_revisions.day.replace("%d",i):wp_document_revisions.days.replace("%d",i)):void 0},t.prototype.roundUp=function(t){return 1>t&&(t=1),t},t.prototype.bindPostDocumentUploadCB=function(){return"undefined"!=typeof uploader&&null!==uploader?uploader.bind("FileUploaded",function(t){return function(e,o,i){return i.response.match("media-upload-error")?void 0:t.postDocumentUpload(o.name,i.response)}}(this)):void 0},t.prototype.updateTimestamps=function(){return this.$(".timestamp").each(function(t){return function(){return t.$(t).text(t.human_time_diff(t.$(t).attr("id")))}}(this))},t.prototype.postDocumentUpload=function(t,e){return"string"==typeof e&&-1!==e.indexOf("error")?this.$(".media-item:first").html(e):(t instanceof Object&&(t=t.name.split(".").pop()),this.hasUpload?void 0:(this.window.jQuery("#content").val(e),this.window.jQuery("#message").hide(),this.window.jQuery("#revision-summary").show(),this.window.jQuery(":button, :submit","#submitpost").removeAttr("disabled"),this.hasUpload=!0,this.window.tb_remove(),"function"==typeof convertEntities&&(wp_document_revisions.postUploadNotice=convertEntities(wp_document_revisions.postUploadNotice)),this.window.jQuery("#post").before(wp_document_revisions.postUploadNotice).prev().fadeIn().fadeOut().fadeIn(),0!==this.window.jQuery("#sample-permalink").length?this.window.jQuery("#sample-permalink").html(this.window.jQuery("#sample-permalink").html().replace(/\<\/span>(\.[a-z0-9]{3,4})?@$/i,wp_document_revisions.extension)):void 0))},t}(),jQuery(document).ready(function(e){return window.WPDocumentRevisions=new t(e)})}).call(this);
