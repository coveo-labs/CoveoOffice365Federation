# CoveoExchange365Federation
Federated Search option between Coveo and Exchange 365/Online using Graph APIs.

## Description
Due to throttling policies on Cloud content it is sometimes very hard to index the original content. For example Office 365, Email.
It contains huge amounts of data. To index it would take months.
To overcome this problem you can execute a federated search against Office 365 (using the Graph API) and blend those results into the Coveo Search pages.

![Federated](/docs/FullSearch.png)


It uses multiple components:
* __Coveo platform__ - hosts the Coveo index and organization for your data, provides the search capabilities.
* __Grap API__ - Microsoft Office 365 API to access content.
* __Coveo Search Pages__ - hosted search page which can be used in the Coveo Platform.

## Limitations
The [MS Graph API](https://developer.microsoft.com/en-us/graph/docs/concepts/query_parameters) has a few limiations:
* It can only return a maximum of 250 results
* Sorting is only possible on date
* Does support searching in both the emails and the attachments
* Does NOT support paging
* Does NOT support folding
* Does NOT reports a score for the result
* Does NOT support highlightning
* Does NOT support excerpts
* Does NOT support facets/refiners
* Does NOT support the exchange online archive account (even if it would it is very, very slow to query)

## How it works
The whole process of doing a federated search against the MS Graph api consists of the following:
* Search Interface is loaded
* A check is made if we are authenticated against Office 365
  * If Not, a login request is made against Office 365 (```buildAuthUrl()```)
  * If there is No ‘Consent’ yet, a Consent dialog will pop-up to access the users data
  * After successful login continue
* A search is performed in the Search Interface (```buildingQuery``` event)
* If Office 365 results are needed
  * The current query is cancelled
  * The Office 365 results are fetched (```searchEmail```)
  * The Office 365 results are transformed to Coveo suitable results (```generateCoveoResults```).
  The function will: add highlightning, get the excerpt, add childs results (based upon conversationId), add groupby values
  * A new query is executed
  * If facets are selected in the email interface, those are transformed to ‘Office 365’ queries (```buildingQuery``` event).
  * In the ```preprocessResults preprocessMoreResults``` event the Office 365 results are inserted on top (if not in the Email interface) of the normal results. When in the Email interface the results from Coveo (which are empty) are completely changed for the Office 365 results, including groupby results.
  The groupby is being calculated based upon the returned results.
* Results are rendered using the normal Coveo templates/Facets

### Custom UI components
Two custom components are used:
```CoveoMyQuick```: Will display a preview/quickview of the email using the body of the email (returned by Graph API).
```CoveoMyAttachment```: Will display a warning that an attachment is present for the result.

### Dependencies
* [MS Graph API javascript SDK](https://unpkg.com/@microsoft/microsoft-graph-client@1.0.0/lib/graph-js-sdk-web.js)
* [JSR](https://kjur.github.io/jsrsasign/jsrsasign-latest-all-min.js)
* [Coveo JS UI](https://docs.coveo.com/en/408)


## How to configure
### Create a new Application in MS dev center
Before you can start using the script and the Search Page, you first need to create a new Application in [App Store](https://apps.dev.microsoft.com/#/appList).
This will result in an Application Id, which you need later.
Create a new 'Web Application'.
Add your Redirect Urls which are your hosted search pages urls (like: https://search.cloud.coveo.com/pages/sewimnijmeijer01/FederateTest2).

Finally set the 'Microsoft Graph Permissions' to:
* Mail.Read
* Mail.Read.Shared
* openid
* User.Read

### Change the Search Page code
In the Coveo Administration Console, Search Pages section. Create a new [Search Page](https://onlinehelp.coveo.com/en/cloud/search_pages.htm).
Edit the page and switch to 'Code' view.
Copy the contents of the [Search Page](/src/FederatedSearchCoveoAndExchange365.html).
If the above is ready, change:
```javascript
const MS_CONFIG = {
  authEndpoint: 'https://login.microsoftonline.com/common/oauth2/v2.0/authorize?',
  redirectUri: 'https://s3.amazonaws.com/static.coveodemo.com/AuthLoginDone.html',
  //The appId is the one you created inside the https://apps.dev.microsoft.com/#/appList
  appId: '00a0000a-a000-00a0-0a0a-000a000a0aa0',
  scopes: 'openid profile User.Read Mail.Read',
  //Max results to return in the all content tab
  maxAll: 2,
  //Max results to return in the email tab
  maxEmail: 50,
};
```
```appId```: Insert the application id you have gathered during the creation of your new application.
```maxAll```: The number of results to show in the 'All content' search interface.
```maxEmail```: The number of results to show in the 'Email' search interface. This should not exceed 250.

## Custom work
If you want to manually want to insert all the code into an existing search page, follow the following procedure:
* First, create a new Application in MS dev center (See How to configure>Create a new Application in MS dev center).
* Open your Search Page in the Coveo Administration Console
* Hit 'view code'
* Insert the following external libraries:
```javascript
  <script src="//ajax.aspnetcdn.com/ajax/jQuery/jquery-2.2.3.min.js"></script>
  <script src="//kjur.github.io/jsrsasign/jsrsasign-latest-all-min.js"></script>
  <script src="//unpkg.com/@microsoft/microsoft-graph-client@1.0.0/lib/graph-js-sdk-web.js"></script>
```
* Insert the following CSS:
```css
  <style>
    .coveo-small {
      font-size: 70%;
      background-color: #F7F8F9;
      padding-left: 20px;
    }
    .coveo-federated-email.coveo-modalBox>.coveo-wrapper>.coveo-body {
      padding: 15px;
    }

    .coveo-federated-email.coveo-modalBox>.coveo-wrapper>.coveo-title {
      text-align: left !important;
    }
  </style>
```
* Insert the [code](/src/Code.js) into the page
* Add the following HTML (just before the ```<div class="coveo-tab-section">```)
```html
  <!-- error message -->
  <div id="error-display" class="page panel panel-danger">
    <div class="panel-heading">
      <h3 class="panel-title" id="error-name"></h3>
    </div>
    <div class="panel-body">
      <pre><code id="error-desc"></code></pre>
    </div>
  </div>
```
* Add the following HTML for the facets:
```html
  <div class="CoveoFacet" data-title="From" data-field="@from" data-tab="Email"></div>
  <div class="CoveoFacet" data-title="To" data-field="@to" data-tab="Email"></div>
  <div class="CoveoFacet" data-title="With Attachment" data-field="@withattach" data-tab="Email"></div>
```
* Add the following HTML (just before the ```<div class="CoveoResultList" data-layout="list" data-wait-animation="fade" data-auto-select-fields-to-include="true">```)
```html
  <div id="federatedHint">A Federated search against Office 365 email messages will be executed.
          <br>Search Email top messages (and attachments). No attachments are retrieved.
  </div>
  <div id="federatedEmail" style="text-align: left;padding:5px">
    <div id="inbox-status" class="panel-body"></div>
  </div>
```
* Add the following result template to your page:

```html
<script id="EmailThread" class="result-template" type="text/html" data-layout="list" data-field-mailbox="">
<div class="coveo-result-frame coveo-email-result">
  <div class="coveo-result-row">
    <div class="coveo-result-cell" style="width:85px; text-align:center; padding-top:7px">
      <span class="CoveoIcon"></span>
      <span class="CoveoMyQuick"></span>
    </div>
    <div class="coveo-result-cell" style="padding-left:15px">
      <div class="coveo-result-row">
        <div class="coveo-result-cell" style="font-size:18px">
          <a class="CoveoResultLink" data-always-open-in-new-window='true'></a>
        </div>
        <div class="coveo-result-cell" style="width:120px; text-align:right; font-size:12px">
          <span class="CoveoFieldValue" data-field="@date" data-helper="emailDateTime"></span>
        </div>
      </div>
      <div class="coveo-result-row">
        <div class="coveo-result-cell" style="font-size:13px;padding-top:5px;padding-bottom:5px;">
          <span class="CoveoText" data-value="From:"></span>
          <span class="CoveoFieldValue" data-field="@from" data-helper="email" data-html-value="true"></span>
          <span class="CoveoText" data-value="To:"></span>
          <span class="CoveoFieldValue" data-field="@recipients" data-helper="email" data-html-value="true"></span>
        </div>
      </div>
      <div class="coveo-result-row">
        <div class="coveo-result-cell" style="padding-top:5px; padding-bottom:5px">
          <span class="CoveoExcerpt"></span>
          <span class="CoveoMyAttachment"></span>
        </div>
      </div>
      <div class="coveo-result-row">
        <div class="coveo-result-cell" style="padding-top:5px; padding-bottom:5px;  font-size:13px;">
          <span class="CoveoResultFolding" data-result-template-id="EmailChildResult" data-more-caption="ShowAllReplies"
            data-less-caption="ShowOnlyMostRelevantReplies"></span>
        </div>
      </div>
    </div>
  </div>
</div>
</script>
```
* And the ```EmailChildResult``` template:
```html
<script id="EmailChildResult" class="result-template" type="text/html">
<div class="coveo-result-frame coveo-email-result" style="font-size: 80%;">
  <div class="coveo-result-row">
    <div class="coveo-result-cell" style="width:56px; text-align:center; padding-top:7px">
      <span class="CoveoIcon" data-small='true'></span>
      <span class="CoveoMyQuick"></span>
    </div>
    <div class="coveo-result-cell" style="padding-left:15px">
      <div class="coveo-result-row">
        <div class="coveo-result-cell" style="font-size:18px">
          <a class="CoveoResultLink"></a>
        </div>
        <div class="coveo-result-cell" style="width:120px; text-align:right; font-size:12px">
          <span class="CoveoFieldValue" data-field="@date" data-helper="emailDateTime"></span>
        </div>
      </div>
      <div class="coveo-result-row">
        <div class="coveo-result-cell" style="font-size:13px;padding-top:5px;padding-bottom:5px;">
          <span class="CoveoText" data-value="From:"></span>
          <span class="CoveoFieldValue" data-field="@from" data-helper="email" data-html-value="true"></span>
          <span class="CoveoText" data-value="To:"></span>
          <span class="CoveoFieldValue" data-field="@recipients" data-helper="email" data-html-value="true"></span>
        </div>
      </div>
      <div class="coveo-result-row">
        <div class="coveo-result-cell" style="padding-top:5px; padding-bottom:5px">
          <span class="CoveoExcerpt"></span>
          <span class="CoveoMyAttachment"></span>
        </div>
      </div>
    </div>
  </div>
</div>
</script>
```

### References
* [MS Graph Javascript SDK](https://docs.microsoft.com/en-us/outlook/rest/javascript-tutorial)
* [MS Graph API](https://developer.microsoft.com/en-us/graph/docs/concepts/query_parameters)
* [Coveo Platform](https://onlinehelp.coveo.com/en/cloud/search_pages.htm)


### Authors
- Wim Nijmeijer (https://github.com/wnijmeijer)
- Jerome Devost (https://github.com/jdevost)
