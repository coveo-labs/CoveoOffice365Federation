/* globals Coveo, __extends, MicrosoftGraph, KJUR, b64utoutf8, _ */

let __emailResults = {};

const MS_CONFIG = {
  authEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?',
  redirectUri: 'https://s3.amazonaws.com/static.coveodemo.com/AuthLoginDone.html',
  //The appId is the one you created inside the https://apps.dev.microsoft.com/#/appList
  appId: '**removed**',
  scopes: 'openid profile User.Read Mail.Read',
  //Max results to return in the all content tab
  maxAll: 2,
  //Max results to return in the email tab
  maxEmail: 50,
};

class Utils {
  static guid() {
    let buf = new Uint16Array(8);
    window.crypto.getRandomValues(buf);

    let randomIds = [];
    buf.forEach(n => {
      const y = '0000' + n.toString(16);
      randomIds.push(y.substr(-4));
    });

    return [randomIds[0], randomIds[1], '-', randomIds[2], '-', randomIds[3], '-', randomIds[4], '-', randomIds[5], randomIds[6], randomIds[7]].join('');
  }

  static htmlDecode(str) {
    let replaceMap = {
      '&quot;': '"',
      '&#44;': ',',
      '&#39;': `'`,
    };

    let value = (str || '').replace(/&(quot|#44|#39);/g, m => replaceMap[m]);
    // remove img tag to prevent unnecessary requests
    value = value.replace(/<\s*img\b[^>]+?>/gi, '');
    // remove html comments, they didn't work well with the workaround below.
    value = value.replace(/<!--[^>]+?-->/gi, '');

    return $('<div/>')
      .html(value)
      .text();
  }

  static htmlEncode(str) {
    let charMap = {
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
    };

    return (str || '').replace(/[<>&"]/g, m => charMap[m]);
  }

  static uriDecode(str) {
    return decodeURIComponent(str || '');
  }
}

//Highlighter for Federated content, MS Graph api does not do highlightning
function getHighlights(str, words) {
  let regex = RegExp(words.join('|'), 'gi'); // case insensitive
  let high = [];
  let match = null;
  if (words.length === 1 && !words[0]) {
    return high;
  }

  while ((match = regex.exec(str))) {
    high.push({ offset: match.index, length: match[0].length });
  }
  return high;
}

//Excerpter for Federated content, MS Graph api does not do excerpts
function getExcerpt(str, words) {
  let excerpt = '';
  let count = 0;
  $.each(words, function(word) {
    let regex = new RegExp('[.\\S\\s ]{50}' + words[word] + '[.\\S\\s ]{50}', 'gi');
    let matches = null;
    while ((matches = regex.exec(str))) {
      excerpt += ' ...' + matches[0] + '...';
      count = count + 1;
      if (count > 3) {
        break;
      }
    }
  });
  return excerpt;
}

// HELPER FUNCTIONS ============================
$(function() {
  if (!Coveo.InterfaceEditor) {
    $('#error-display', window.parent.document).hide();
  }
});

//Render the error
function renderError(error, description) {
  $('#error-name', window.parent.document).text('An error occurred: ' + Utils.uriDecode(error));
  $('#error-desc', window.parent.document).text(Utils.uriDecode(description));
  $('#error-display', window.parent.document).show();
}

//Get the hash parameters
function parseHashParams(hash) {
  let params = hash.slice(1).split('&');

  let paramarray = {};
  params.forEach(function(param) {
    param = param.split('=');
    paramarray[param[0]] = param[1];
  });

  return paramarray;
}

//Clear the user State
function clearUserState() {
  // Clear session
  sessionStorage.clear();
  MS_CONFIG.graphClient = null;
}

// OAUTH FUNCTIONS =============================

//Build the authentication url against office
function buildAuthUrl() {
  // Generate random values for state and nonce
  sessionStorage.authState = Utils.guid();
  sessionStorage.authNonce = Utils.guid();

  let authParams = {
    response_type: 'id_token token',
    client_id: MS_CONFIG.appId,
    redirect_uri: MS_CONFIG.redirectUri,
    scope: MS_CONFIG.scopes,
    state: sessionStorage.authState,
    nonce: sessionStorage.authNonce,
    response_mode: 'fragment',
  };

  return MS_CONFIG.authEndpoint + $.param(authParams);
}

//Handle the response from the authentication process against Office
function handleTokenResponse(hash) {
  // clear tokens
  sessionStorage.removeItem('idToken');

  let tokenresponse = parseHashParams(hash);
  // Check that state is what we sent in sign in request
  if (tokenresponse.state !== sessionStorage.authState) {
    // Failed validation
    return;
  }
  sessionStorage.removeItem('authState');
  sessionStorage.setItem('msgraphAccessToken', tokenresponse.access_token);

  if (window._ms_graph_callback) {
    MS_CONFIG.graphClient = null;
    window._ms_graph_callback();
    window._ms_graph_callback = null;
  }
  sessionStorage.idToken = tokenresponse.id_token;

  validateIdToken(function(isValid) {
    let hash = '#';
    if (!isValid) {
      clearUserState();
      // Report error
      hash = '#error=Invalid+ID+token&error_description=ID+token+failed+validation,+please+try+signing+in+again.';
    }
    window.location.hash = hash;
  });
}

//Validate the token
function validateIdToken(callback) {
  if (!sessionStorage.idToken) {
    callback(false);
  }

  // JWT is in three parts seperated by '.'
  let tokenParts = sessionStorage.idToken.split('.');
  if (tokenParts.length !== 3) {
    callback(false);
  }

  // Parse the token parts
  let payload = KJUR.jws.JWS.readSafeJSONString(b64utoutf8(tokenParts[1]));
  // Check the audience
  if (payload.aud !== MS_CONFIG.appId) {
    callback(false);
  }
  if (payload.nonce !== sessionStorage.authNonce) {
    callback(false);
  }
  sessionStorage.removeItem('authNonce');

  // Check the issuer
  // Should be https://login.microsoftonline.com/{tenantid}/v2.0
  if (payload.iss !== 'https://login.microsoftonline.com/' + payload.tid + '/v2.0') {
    callback(false);
  }

  // Now that we've passed our checks, save the bits of data we need from the token.
  sessionStorage.userDisplayName = payload.name;
  sessionStorage.userSigninName = payload.preferred_username;

  // Per the docs at:
  // https://azure.microsoft.com/en-us/documentation/articles/active-directory-v2-protocols-implicit/#send-the-sign-in-request
  // Check if this is a consumer account so we can set domain_hint properly
  sessionStorage.userDomainType = payload.tid === '**removed**' ? 'consumers' : 'organizations';

  callback(true);
}

function onLoginDoneMessage(event) {
  handleTokenResponse(event.data);
}
window.addEventListener('message', onLoginDoneMessage, false);

//After expired information, refresh the token silently
function loginToMsGraph(callback) {
  const authUrl = buildAuthUrl();
  window._ms_graph_callback = callback; // use for retry
  MS_CONFIG.graphClient = null;
  window.open(authUrl, 'MS_LOGIN', 'width=600,height=400,resizable,scrollbars=yes,status=1');
}

// Helper method to validate token and refresh if needed
function getAccessToken(callback) {
  const token = sessionStorage.getItem('msgraphAccessToken');
  if (callback) {
    callback(token);
  }
  return token;
}

// OUTLOOK API FUNCTIONS =======================
function getGraphClient() {
  if (!MS_CONFIG.graphClient) {
    let token = getAccessToken();
    if (!token) {
      return null;
    }
    MS_CONFIG.graphClient = MicrosoftGraph.Client.init({
      authProvider: done => {
        // Just return the token
        done(null, token);
      },
    });
  }
  return MS_CONFIG.graphClient;
}

function getEmails(apicall, nr, callback, isRetry) {
  let graphClient = getGraphClient();

  if (!graphClient) {
    return loginToMsGraph(function() {
      getEmails(apicall, nr, callback, isRetry);
    });
  }

  graphClient
    .api(apicall)
    .top(nr)
    //Fields to retrieve
    .select('subject,from,toRecipients,receivedDateTime,webLink,bodyPreview,body,hasAttachments,conversationId')
    .get((err, res) => {
      if (err && err.statusCode === 401 && !isRetry) {
        clearUserState(); // will clear the ms graph client, forcing a login.
        // Renew token and try again
        return getEmails(apicall, nr, callback, true);
      }
      if (err) {
        console.error(err);
        callback(null, err);
      } else {
        callback(res.value);
      }
    });
}

//Search for emails
function searchForEmail(terms, filter, nr, callback) {
  //Get latest if no search terms
  let apicall = '/me/mailfolders/inbox/messages';
  if (terms || filter) {
    apicall = `/me/messages?$search="${filter || ''} ${terms || ''}"`;
  }

  getEmails(apicall, nr, callback);
}

//Search Email
function searchEmail(terms, filter, nr, callback) {
  $('#message-list').empty();
  $('#inbox').show();

  searchForEmail(terms, filter, nr, function(messages, error) {
    if (error) {
      renderError('getUserInboxMessages failed', error);
    } else {
      let comment = '';
      let fontWeight = 'normal';
      if (nr > MS_CONFIG.maxAll) {
        //Big Email search
        if (messages.length >= 50) {
          comment = ' (Maximum reached)';
        }
        comment = messages.length + comment + ' results from Office 365, sorted by date.';
      } else {
        //Smaller, only show top X result
        comment = 'We also found emails in Office 365, For more see tab "Email".';
        fontWeight = 'bold';
      }
      $('#inbox-status')
        .text(comment)
        .css('font-size', '100%')
        .css('font-weight', fontWeight);

      __emailResults = generateCoveoResults(messages);
      if (!messages.length) {
        let statusText = '';
        if (nr > MS_CONFIG.maxAll) {
          statusText = 'NO Results found in Office 365, try another query.';
        }
        $('#inbox-status').text(statusText);
      }
      callback(__emailResults);
    }
  });
}

//Check if we have the value in our array, if not add it, if so add the numberofresults
function doWeHaveIt(tocheck, value) {
  let wehaveit = false;
  $.each(tocheck, function(index, obj) {
    if (obj.value === value) {
      wehaveit = true;
      tocheck[index].numberOfResults = tocheck[index].numberOfResults + 1;
    }
  });
  if (!wehaveit) {
    tocheck.push({ value: value, lookupValue: value, numberOfResults: 1, score: 0, valueType: 'Standard' });
  }
  return tocheck;
}

//Add the result to our array, if we already have the conversationId add it as a child, so we can support folding
function addResult(tocheck, addobj) {
  let wehaveit = false;
  $.each(tocheck, function(index, obj) {
    if (obj.conversationId === addobj.conversationId) {
      wehaveit = true;
      if (!tocheck[index].childResults) {
        tocheck[index].childResults = [];
      }
      tocheck[index].childResults.push(addobj);
    }
  });
  if (!wehaveit) {
    tocheck.push(addobj);
  }
  return tocheck;
}

//Build filter for MS Graph Api (facet selection)
function buildFilter(field, stringvalue, state) {
  let filter = '';
  let addedstring = '';
  if (stringvalue) {
    addedstring = `'`;
  }
  if (state.length) {
    _.each(state, function(res) {
      if (!filter) {
        filter = ' ' + field + ':' + addedstring + res + addedstring;
      } else {
        filter = filter + ' or ' + field + ':' + addedstring + res + addedstring;
      }
    });
    if (filter) {
      filter = '(' + filter + ')';
    }
  }
  return filter;
}

//Generate Coveo results based upon the messages retrieved from Office
function generateCoveoResults(messages) {
  let coveoResults = {
    totalCount: messages.length,
    totalCountFiltered: messages.length,
  };
  let results = [];
  let fromval = [];
  let toval = [];
  let attval = [];
  _.each(messages, function(result) {
    //Build raw content
    let raw = {
      collection: 'default',
      date: result.receivedDateTime,
      sysfiletype: 'exchangemessage',
      hasAttachments: result.hasAttachments,
      filetype: 'exchangemessage',
      from: result.from.emailAddress.name,
      content: result.body.content,
    };
    let recips = [];

    //Add groupby values
    attval = doWeHaveIt(attval, result.hasAttachments.toString());
    fromval = doWeHaveIt(fromval, result.from.emailAddress.name);
    _.each(result.toRecipients, function(recip) {
      recips.push(recip.emailAddress.name);
      toval = doWeHaveIt(toval, recip.emailAddress.name);
    });
    raw.recipients = recips.join(';');
    raw.mailbox = 'mailbox@mailbox.com';
    raw.sysmailbox = 'mailbox@mailbox.com';

    //Get highlights
    let words = Coveo.$('.CoveoSearchInterface')
      .coveo('state', 'q')
      .split(' ');
    let titlehigh = getHighlights(result.subject, words);
    let excerpt = getExcerpt(Utils.htmlDecode(result.body.content), words);
    if (!excerpt) {
      excerpt = result.bodyPreview;
    }
    let excerptHigh = getHighlights(excerpt, words);

    //add the result to the results array
    results = addResult(results, {
      title: result.subject,
      conversationId: result.conversationId,
      childResults: [],
      uri: result.webLink,
      clickUri: result.webLink,
      excerptHighlights: excerptHigh,
      firstSentencesHighlights: [],
      printableUriHighlights: [],
      titleHighlights: titlehigh,
      firstSentences: result.bodyPreview,
      excerpt: excerpt,
      hasHtmlVersion: true,
      printableUri: result.webLink,
      raw: raw,
    });
  });

  //add group by values
  coveoResults.groupByResults = [
    { field: 'from', Field: 'from', values: fromval }, // from
    { field: 'to', Field: 'to', values: toval }, // to
    { field: 'withattachment', Field: 'withattachment', values: attval },
  ];
  coveoResults.results = results;
  return coveoResults;
}

let preProcessResults = function(e, data) {
  if (__emailResults.results) {
    if (Coveo.$('.CoveoSearchInterface').coveo('state', 't') === 'Email') {
      //Add our internal results into the data.result set
      data.results.totalCount = __emailResults.totalCount;
      data.results.totalCountFiltered = __emailResults.totalCountFiltered;
      data.results.results = [].concat(__emailResults.results);
      data.results.groupByResults = [].concat(__emailResults.groupByResults);
      $('.CoveoResultList').fadeIn();
    } else {
      //We need to add the federated results to the top
      __emailResults.results.forEach(function(result) {
        data.results.results.splice(0, 0, result);
      });
    }
  }
  __emailResults = {};
};

//Check if current tab is Email, if so replace results by MS data
let onBuildQuery = function(e, args) {
  const isEmailTab = Coveo.$('.CoveoSearchInterface').coveo('state', 't') === 'Email';
  if (isEmailTab) {
    $('.coveo-results-header').hide();
    $('.CoveoResultsPerPage').hide();
    $('.CoveoPager').hide();
    $('.CoveoResultList').fadeOut();
  }
  $('#federatedHint').hide();

  if (!__emailResults.results) {
    // We cancel the current query, we will trigger manually after getting the emails (executeQuery)
    args.cancel = true;
    $('#inbox-status').text('Getting results from Office 365...');
    $('#inbox-status').css('font-weight', 'bold');
    $('#inbox-status').css('font-size', '120%');
    Coveo.$('.CoveoSearchInterface').addClass('coveo-executing-query');

    // Add filters, based upon facet selections
    let filter = '';
    if (isEmailTab) {
      let filterfrom = buildFilter('from', true, Coveo.$('.CoveoSearchInterface').coveo('state', 'f:@from'));
      let filterto = buildFilter('recipients', true, Coveo.$('.CoveoSearchInterface').coveo('state', 'f:@to'));
      let filteratt = buildFilter('hasAttachments', false, Coveo.$('.CoveoSearchInterface').coveo('state', 'f:@withattach'));

      filter = filterto + filterfrom + filteratt;
    }

    const max = isEmailTab ? MS_CONFIG.maxEmail : MS_CONFIG.maxAll;
    searchEmail(Coveo.$('.CoveoSearchInterface').coveo('state', 'q'), filter, max, function() {
      Coveo.$('#search').coveo('executeQuery');
    });
  } else {
    $('#federatedHint').show();
  }

  if (!isEmailTab) {
    $('.coveo-facet-column').show();
    $('.coveo-results-header').show();
    $('.CoveoPager').show();
    $('.CoveoResultsPerPage').show();
  }
};

$('#search').on('preprocessResults preprocessMoreResults', preProcessResults);

//Check if current tab is Email, if so replace results by MS data
$('#search').on('buildingQuery', onBuildQuery);

//***************************
//Custom Quickview for federated email result
//***************************
const MyQuick = function(element, options, bindings, result) {
  __extends(MyQuick, Coveo.Component);
  this.element = element;
  this.options = Coveo.ComponentOptions.initComponentOptions(element, MyQuick, options);
  this.bindings = bindings;
  this.result = result;
  //Change CSS if not in email interface
  if (Coveo.$('.CoveoSearchInterface').coveo('state', 't') !== 'Email') {
    $(this.element)
      .closest('.coveo-result-frame')
      .addClass('coveo-small');
  }
  Coveo.$('<div class="coveo-sprites-quickview"></div><div class="coveo-caption-for-icon" tabindex="0">Preview</div></div>')
    .click({ result: this.result }, function(e) {
      let html = e.data.result.raw['content'];
      let itemDebugResultsJSONContainer = Coveo.$$('div');
      itemDebugResultsJSONContainer.el.innerHTML = html;

      let body = Coveo.$$('div');
      body.append(itemDebugResultsJSONContainer.el);

      Coveo.ModalBox.open(body.el, {
        title: e.data.result.title,
        className: 'coveo-debug coveo-federated-email',
        titleClose: true,
        overlayClose: true,
        validation: function() {
          return true;
        },
        sizeMod: 'big',
      });
    })

    .appendTo(this.element);
};
MyQuick.ID = 'MyQuick';
Coveo.CoveoJQuery.registerAutoCreateComponent(MyQuick);

//***************************
//Attachment indicator
//***************************
const MyAttachment = function(element, options, bindings, result) {
  __extends(MyAttachment, Coveo.Component);
  this.element = element;
  this.options = Coveo.ComponentOptions.initComponentOptions(element, MyAttachment, options);
  this.bindings = bindings;
  this.result = result;
  if (this.result.raw.hasAttachments) {
    Coveo.$(
      `<div style="width:100%;border-top:1px solid #BCC3CA;padding:15px">
        <span class="CoveoIcon coveo-sprites-attach"></span>
        <span style="font-size:13px;padding:5px;">Contains attachment (found result could also be inside the attachment).</span>
      </div>`
    ).appendTo(this.element);
  }
};
MyAttachment.ID = 'MyAttachment';
Coveo.CoveoJQuery.registerAutoCreateComponent(MyAttachment);
