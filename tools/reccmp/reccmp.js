// reccmp.js
/* global data */

// Unwrap array of functions into a dictionary with address as the key.
const dataDict = Object.fromEntries(data.map(row => [row.address, row]));

function getDataByAddr(addr) {
  return dataDict[addr];
}

//
// Pure functions
//

function formatAsm(entries, addrOption) {
  const output = [];

  const createTh = (text) => {
    const th = document.createElement('th');
    th.innerText = text;
    return th;
  };

  const createTd = (text, className = '') => {
    const td = document.createElement('td');
    td.innerText = text;
    td.className = className;
    return td;
  };

  entries.forEach(obj => {
    // These won't all be present. You get "both" for an equal node
    // and orig/recomp for a diff.
    const { both = [], orig = [], recomp = [] } = obj;

    output.push(...both.map(([addr, line, recompAddr]) => {
      const tr = document.createElement('tr');
      tr.appendChild(createTh(addr));
      tr.appendChild(createTh(recompAddr));
      tr.appendChild(createTd(line));
      return tr;
    }));

    output.push(...orig.map(([addr, line]) => {
      const tr = document.createElement('tr');
      tr.appendChild(createTh(addr));
      tr.appendChild(createTh(''));
      tr.appendChild(createTd(`-${line}`, 'diffneg'));
      return tr;
    }));

    output.push(...recomp.map(([addr, line]) => {
      const tr = document.createElement('tr');
      tr.appendChild(createTh(''));
      tr.appendChild(createTh(addr));
      tr.appendChild(createTd(`+${line}`, 'diffpos'));
      return tr;
    }));
  });

  return output;
}

// Special internal values to ensure this sort order for matching column:
// 1. Stub
// 2. Any match percentage [0.0, 1.0)
// 3. Effective match
// 4. Actual 100% match
function matchingColAdjustment(row) {
  if ('stub' in row) {
    return -1;
  }

  if ('effective' in row) {
    return 1.0;
  }

  if (row.matching === 1.0) {
    return 1000;
  }

  return row.matching;
}

function getCppClass(str) {
  const idx = str.indexOf('::');
  if (idx !== -1) {
    return str.slice(0, idx);
  }

  return str;
}

// Clamp string length to specified length and pad with ellipsis
function stringTruncate(str, maxlen = 20) {
  str = getCppClass(str);
  if (str.length > maxlen) {
    return `${str.slice(0, maxlen)}...`;
  }

  return str;
}

function getMatchPercentText(row) {
  if ('stub' in row) {
    return 'stub';
  }

  if ('effective' in row) {
    return '100.00%*';
  }

  return (row.matching * 100).toFixed(2) + '%';
}

function countDiffs(row) {
  const { diff = '' } = row;
  if (diff === '') {
    return '';
  }

  const diffs = diff.map(([slug, subgroups]) => subgroups).flat();
  const diffLength = diffs.filter(d => !('both' in d)).length;
  const diffWord = diffLength === 1 ? 'diff' : 'diffs';
  return diffLength === 0 ? '' : `${diffLength} ${diffWord}`;
}

// Helper for this set/remove attribute block
function setBooleanAttribute(element, attribute, value) {
  if (value) {
    element.setAttribute(attribute, '');
  } else {
    element.removeAttribute(attribute);
  }
}

function copyToClipboard(value) {
  navigator.clipboard.writeText(value);
}

const PAGE_SIZE = 200;

//
// Global state
//

class ListingState {
  constructor() {
    this._query = '';
    this._sortCol = 'address';
    this._filterType = 1;
    this._sortDesc = false;
    this._hidePerfect = false;
    this._hideStub = false;
    this._showRecomp = false;
    this._expanded = {};
    this._page = 0;

    this._listeners = [];

    this._results = [];
    this.updateResults();
  }

  addListener(fn) {
    this._listeners.push(fn);
  }

  callListeners() {
    for (const fn of this._listeners) {
      fn();
    }
  }

  isExpanded(addr) {
    return addr in this._expanded;
  }

  toggleExpanded(addr) {
    this.setExpanded(addr, !this.isExpanded(addr));
  }

  setExpanded(addr, value) {
    if (value) {
      this._expanded[addr] = true;
    } else {
      delete this._expanded[addr];
    }
  }

  updateResults() {
    const filterFn = this.rowFilterFn.bind(this);
    const sortFn = this.rowSortFn.bind(this);

    this._results = data.filter(filterFn).sort(sortFn);

    // Set _page directly to avoid double call to listeners.
    this._page = this.pageClamp(this.page);
    this.callListeners();
  }

  pageSlice() {
    return this._results.slice(this.page * PAGE_SIZE, (this.page + 1) * PAGE_SIZE);
  }

  resultsCount() {
    return this._results.length;
  }

  pageCount() {
    return Math.ceil(this._results.length / PAGE_SIZE);
  }

  maxPage() {
    return Math.max(0, this.pageCount() - 1);
  }

  // A list showing the range of each page based on the sort column and direction.
  pageHeadings() {
    if (this._results.length === 0) {
      return [];
    }

    const headings = [];

    for (let i = 0; i < this.pageCount(); i++) {
      const startIdx = i * PAGE_SIZE;
      const endIdx = Math.min(this._results.length, ((i + 1) * PAGE_SIZE)) - 1;

      let start = this._results[startIdx][this.sortCol];
      let end = this._results[endIdx][this.sortCol];

      if (this.sortCol === 'matching') {
        start = getMatchPercentText(this._results[startIdx]);
        end = getMatchPercentText(this._results[endIdx]);
      }

      headings.push([i, stringTruncate(start), stringTruncate(end)]);
    }

    return headings;
  }

  rowFilterFn(row) {
    // Destructuring sets defaults for optional values from this object.
    const {
      effective = false,
      stub = false,
      diff = '',
      name,
      address,
      matching
    } = row;

    if (this.hidePerfect && (effective || matching >= 1)) {
      return false;
    }

    if (this.hideStub && stub) {
      return false;
    }

    if (this.query === '') {
      return true;
    }

    // Name/addr search
    if (this.filterType === 1) {
      return (
        address.includes(this.query) ||
        name.toLowerCase().includes(this.query)
      );
    }

    // no diff for review.
    if (diff === '') {
      return false;
    }

    // special matcher for combined diff
    const anyLineMatch = ([addr, line]) => line.toLowerCase().trim().includes(this.query);

    // Flatten all diff groups for the search
    const diffs = diff.map(([slug, subgroups]) => subgroups).flat();
    for (const subgroup of diffs) {
      const { both = [], orig = [], recomp = [] } = subgroup;

      // If search includes context
      if (this.filterType === 2 && both.some(anyLineMatch)) {
        return true;
      }

      if (orig.some(anyLineMatch) || recomp.some(anyLineMatch)) {
        return true;
      }
    }

    return false;
  }

  rowSortFn(rowA, rowB) {
    const valA = this.sortCol === 'matching'
      ? matchingColAdjustment(rowA)
      : rowA[this.sortCol];

    const valB = this.sortCol === 'matching'
      ? matchingColAdjustment(rowB)
      : rowB[this.sortCol];

    if (valA > valB) {
      return this.sortDesc ? -1 : 1;
    } else if (valA < valB) {
      return this.sortDesc ? 1 : -1;
    }

    return 0;
  }

  pageClamp(page) {
    return Math.max(0, Math.min(page, this.maxPage()));
  }

  get page() {
    return this._page;
  }

  set page(page) {
    this._page = this.pageClamp(page);
    this.callListeners();
  }

  get filterType() {
    return parseInt(this._filterType);
  }

  set filterType(value) {
    value = parseInt(value);
    if (value >= 1 && value <= 3) {
      this._filterType = value;
    }
    this.updateResults();
  }

  get query() {
    return this._query;
  }

  set query(value) {
    // Normalize search string
    this._query = value.toLowerCase().trim();
    this.updateResults();
  }

  get showRecomp() {
    return this._showRecomp;
  }

  set showRecomp(value) {
    // Don't sort by the recomp column we are about to hide
    if (!value && this.sortCol === 'recomp') {
      this._sortCol = 'address';
    }

    this._showRecomp = value;
    this.callListeners();
  }

  get sortCol() {
    return this._sortCol;
  }

  set sortCol(column) {
    if (column === this._sortCol) {
      this._sortDesc = !this._sortDesc;
    } else {
      this._sortCol = column;
    }

    this.updateResults();
  }

  get sortDesc() {
    return this._sortDesc;
  }

  set sortDesc(value) {
    this._sortDesc = value;
    this.updateResults();
  }

  get hidePerfect() {
    return this._hidePerfect;
  }

  set hidePerfect(value) {
    this._hidePerfect = value;
    this.updateResults();
  }

  get hideStub() {
    return this._hideStub;
  }

  set hideStub(value) {
    this._hideStub = value;
    this.updateResults();
  }
}

const appState = new ListingState();

//
// Custom elements
//

// Sets sort indicator arrow based on element attributes.
class SortIndicator extends window.HTMLElement {
  static observedAttributes = ['data-sort'];

  attributeChangedCallback(name, oldValue, newValue) {
    if (newValue === null) {
      // Reserve space for blank indicator so column width stays the same
      this.innerHTML = '&nbsp;';
    } else {
      this.innerHTML = newValue === 'asc' ? '&#9650;' : '&#9660;';
    }
  }
}

class FuncRow extends window.HTMLElement {
  connectedCallback() {
    if (this.shadowRoot !== null) {
      return;
    }

    const template = document.querySelector('template#funcrow-template').content;
    const shadow = this.attachShadow({ mode: 'open' });
    shadow.appendChild(template.cloneNode(true));
    shadow.querySelector(':host > div[data-col="name"]').addEventListener('click', evt => {
      this.dispatchEvent(new Event('name-click'));
    });
  }

  get address() {
    return this.getAttribute('data-address');
  }
}

class NoDiffMessage extends window.HTMLElement {
  connectedCallback() {
    if (this.shadowRoot !== null) {
      return;
    }

    const template = document.querySelector('template#nodiff-template').content;
    const shadow = this.attachShadow({ mode: 'open' });
    shadow.appendChild(template.cloneNode(true));
  }
}

class CanCopy extends window.HTMLElement {
  connectedCallback() {
    if (this.shadowRoot !== null) {
      return;
    }

    const template = document.querySelector('template#can-copy-template').content;
    const shadow = this.attachShadow({ mode: 'open' });
    shadow.appendChild(template.cloneNode(true));

    const el = shadow.querySelector('slot').assignedNodes()[0];
    el.addEventListener('mouseout', evt => { this.copied = false; });
    el.addEventListener('click', evt => {
      copyToClipboard(evt.target.textContent);
      this.copied = true;
    });
  }

  get copied() {
    return this.getAttribute('copied');
  }

  set copied(value) {
    if (value) {
      setTimeout(() => { this.copied = false; }, 2000);
    }
    setBooleanAttribute(this, 'copied', value);
  }
}

// Displays asm diff for the given @data-address value.
class DiffRow extends window.HTMLElement {
  connectedCallback() {
    if (this.shadowRoot !== null) {
      return;
    }

    const template = document.querySelector('template#diffrow-template').content;
    const shadow = this.attachShadow({ mode: 'open' });
    shadow.appendChild(template.cloneNode(true));
  }

  get address() {
    return this.getAttribute('data-address');
  }

  set address(value) {
    this.setAttribute('data-address', value);
  }
}

class DiffDisplayOptions extends window.HTMLElement {
  static observedAttributes = ['data-option'];

  connectedCallback() {
    if (this.shadowRoot !== null) {
      return;
    }

    const shadow = this.attachShadow({ mode: 'open' });
    shadow.innerHTML = `
      <style>
        fieldset {
          align-items: center;
          display: flex;
          margin-bottom: 20px;
        }

        label {
          margin-right: 10px;
          user-select: none;
        }

        label, input {
          cursor: pointer;
        }
      </style>
      <fieldset>
        <legend>Address display:</legend>
        <input type="radio" id="showNone" name="addrDisplay" value=0>
        <label for="showNone">None</label>
        <input type="radio" id="showOrig" name="addrDisplay" value=1>
        <label for="showOrig">Original</label>
        <input type="radio" id="showBoth" name="addrDisplay" value=2>
        <label for="showBoth">Both</label>
      </fieldset>`;

    shadow.querySelectorAll('input[type=radio]').forEach(radio => {
      const checked = this.option === radio.getAttribute('value');
      setBooleanAttribute(radio, 'checked', checked);

      radio.addEventListener('change', evt => (this.option = evt.target.value));
    });
  }

  set option(value) {
    this.setAttribute('data-option', parseInt(value));
  }

  get option() {
    return this.getAttribute('data-option') ?? 1;
  }

  attributeChangedCallback(name, oldValue, newValue) {
    if (name !== 'data-option') {
      return;
    }

    this.dispatchEvent(new Event('change'));
  }
}

class DiffDisplay extends window.HTMLElement {
  static observedAttributes = ['data-option'];

  connectedCallback() {
    if (this.querySelector('diff-display-options') !== null) {
      return;
    }

    const optControl = new DiffDisplayOptions();
    optControl.option = this.option;
    optControl.addEventListener('change', evt => (this.option = evt.target.option));
    this.appendChild(optControl);

    const div = document.createElement('div');
    const obj = getDataByAddr(this.address);

    const createHeaderLine = (text, className) => {
      const div = document.createElement('div');
      div.textContent = text;
      div.className = className;
      return div;
    };

    const groups = obj.diff;
    groups.forEach(([slug, subgroups]) => {
      const secondTable = document.createElement('table');
      secondTable.classList.add('diffTable');

      const hdr = document.createElement('div');
      hdr.appendChild(createHeaderLine('---', 'diffneg'));
      hdr.appendChild(createHeaderLine('+++', 'diffpos'));
      hdr.appendChild(createHeaderLine(slug, 'diffslug'));
      div.appendChild(hdr);

      const tbody = document.createElement('tbody');
      secondTable.appendChild(tbody);

      const diffs = formatAsm(subgroups, this.option);
      for (const el of diffs) {
        tbody.appendChild(el);
      }

      div.appendChild(secondTable);
    });

    this.appendChild(div);
  }

  get address() {
    return this.getAttribute('data-address');
  }

  set address(value) {
    this.setAttribute('data-address', value);
  }

  get option() {
    return this.getAttribute('data-option') ?? 1;
  }

  set option(value) {
    this.setAttribute('data-option', value);
  }
}

class ListingOptions extends window.HTMLElement {
  constructor() {
    super();

    // Register to receive updates
    appState.addListener(() => this.onUpdate());

    const input = this.querySelector('input[type=search]');
    input.oninput = evt => (appState.query = evt.target.value);

    const hidePerf = this.querySelector('input#cbHidePerfect');
    hidePerf.onchange = evt => (appState.hidePerfect = evt.target.checked);
    hidePerf.checked = appState.hidePerfect;

    const hideStub = this.querySelector('input#cbHideStub');
    hideStub.onchange = evt => (appState.hideStub = evt.target.checked);
    hideStub.checked = appState.hideStub;

    const showRecomp = this.querySelector('input#cbShowRecomp');
    showRecomp.onchange = evt => (appState.showRecomp = evt.target.checked);
    showRecomp.checked = appState.showRecomp;

    this.querySelector('button#pagePrev').addEventListener('click', evt => {
      appState.page = appState.page - 1;
    });

    this.querySelector('button#pageNext').addEventListener('click', evt => {
      appState.page = appState.page + 1;
    });

    this.querySelector('select#pageSelect').addEventListener('change', evt => {
      appState.page = evt.target.value;
    });

    this.querySelectorAll('input[name=filterType]').forEach(radio => {
      const checked = appState.filterType === parseInt(radio.getAttribute('value'));
      setBooleanAttribute(radio, 'checked', checked);

      radio.onchange = evt => (appState.filterType = radio.getAttribute('value'));
    });

    this.onUpdate();
  }

  onUpdate() {
    // Update input placeholder based on search type
    this.querySelector('input[type=search]').placeholder = appState.filterType === 1
      ? 'Search for offset or function name...'
      : 'Search for instruction...';

    // Update page number and max page
    this.querySelector('fieldset#pageDisplay > legend').textContent = `Page ${appState.page + 1} of ${Math.max(1, appState.pageCount())}`;

    // Disable prev/next buttons on first/last page
    setBooleanAttribute(this.querySelector('button#pagePrev'), 'disabled', appState.page === 0);
    setBooleanAttribute(this.querySelector('button#pageNext'), 'disabled', appState.page === appState.maxPage());

    // Update page select dropdown
    const pageSelect = this.querySelector('select#pageSelect');
    setBooleanAttribute(pageSelect, 'disabled', appState.resultsCount() === 0);
    pageSelect.innerHTML = '';

    if (appState.resultsCount() === 0) {
      const opt = document.createElement('option');
      opt.textContent = '- no results -';
      pageSelect.appendChild(opt);
    } else {
      for (const row of appState.pageHeadings()) {
        const opt = document.createElement('option');
        opt.value = row[0];
        if (appState.page === row[0]) {
          opt.setAttribute('selected', '');
        }

        const [start, end] = [row[1], row[2]];

        opt.textContent = `${appState.sortCol}: ${start} to ${end}`;
        pageSelect.appendChild(opt);
      }
    }

    // Update row count
    this.querySelector('#rowcount').textContent = `${appState.resultsCount()}`;
  }
}

// Main application.
class ListingTable extends window.HTMLElement {
  constructor() {
    super();

    // Register to receive updates
    appState.addListener(() => this.somethingChanged());
  }

  setDiffRow(address, shouldExpand) {
    const tbody = this.querySelector('tbody');
    const funcrow = tbody.querySelector(`func-row[data-address="${address}"]`);
    if (funcrow === null) {
      return;
    }

    const existing = tbody.querySelector(`diff-row[data-address="${address}"]`);
    if (existing !== null) {
      if (!shouldExpand) {
        tbody.removeChild(existing);
      }

      return;
    }

    const diffrow = document.createElement('diff-row');
    diffrow.address = address;

    // Decide what goes inside the diff row.
    const obj = getDataByAddr(address);

    if ('stub' in obj) {
      const msg = document.createElement('no-diff');
      const p = document.createElement('div');
      p.innerText = 'Stub. No diff.';
      msg.appendChild(p);
      diffrow.appendChild(msg);
    } else if (obj.diff.length === 0) {
      const msg = document.createElement('no-diff');
      const p = document.createElement('div');
      p.innerText = 'Identical function - no diff';
      msg.appendChild(p);
      diffrow.appendChild(msg);
    } else {
      const dd = new DiffDisplay();
      dd.option = '1';
      dd.address = address;
      diffrow.appendChild(dd);
    }

    // Insert the diff row after the parent func row.
    tbody.insertBefore(diffrow, funcrow.nextSibling);
  }

  connectedCallback() {
    const thead = this.querySelector('thead');
    const headers = thead.querySelectorAll('th:not([data-no-sort])'); // TODO
    headers.forEach(th => {
      const col = th.getAttribute('data-col');
      if (col) {
        const span = th.querySelector('span');
        if (span) {
          span.addEventListener('click', evt => { appState.sortCol = col; });
        }
      }
    });

    this.somethingChanged();
  }

  somethingChanged() {
    // Toggle recomp/diffs column
    setBooleanAttribute(this.querySelector('table'), 'show-recomp', appState.showRecomp);
    this.querySelectorAll('func-row[data-address]').forEach(row => {
      setBooleanAttribute(row, 'show-recomp', appState.showRecomp);
    });

    const thead = this.querySelector('thead');
    const headers = thead.querySelectorAll('th');

    // Update sort indicator
    headers.forEach(th => {
      const col = th.getAttribute('data-col');
      const indicator = th.querySelector('sort-indicator');
      if (indicator === null) {
        return;
      }

      if (appState.sortCol === col) {
        indicator.setAttribute('data-sort', appState.sortDesc ? 'desc' : 'asc');
      } else {
        indicator.removeAttribute('data-sort');
      }
    });

    // Add the rows
    const tbody = this.querySelector('tbody');
    tbody.innerHTML = ''; // ?

    for (const obj of appState.pageSlice()) {
      const row = document.createElement('func-row');
      row.setAttribute('data-address', obj.address); // ?
      row.addEventListener('name-click', evt => {
        appState.toggleExpanded(obj.address);
        this.setDiffRow(obj.address, appState.isExpanded(obj.address));
      });
      setBooleanAttribute(row, 'show-recomp', appState.showRecomp);
      setBooleanAttribute(row, 'expanded', appState.isExpanded(row));

      const items = [
        ['address', obj.address],
        ['recomp', obj.recomp],
        ['name', obj.name],
        ['diffs', countDiffs(obj)],
        ['matching', getMatchPercentText(obj)]
      ];

      items.forEach(([slotName, content]) => {
        const div = document.createElement('span');
        div.setAttribute('slot', slotName);
        div.innerText = content;
        row.appendChild(div);
      });

      tbody.appendChild(row);

      if (appState.isExpanded(obj.address)) {
        this.setDiffRow(obj.address, true);
      }
    }
  }
}

window.onload = () => {
  window.customElements.define('listing-table', ListingTable);
  window.customElements.define('listing-options', ListingOptions);
  window.customElements.define('diff-display', DiffDisplay);
  window.customElements.define('diff-display-options', DiffDisplayOptions);
  window.customElements.define('sort-indicator', SortIndicator);
  window.customElements.define('func-row', FuncRow);
  window.customElements.define('diff-row', DiffRow);
  window.customElements.define('no-diff', NoDiffMessage);
  window.customElements.define('can-copy', CanCopy);
};
