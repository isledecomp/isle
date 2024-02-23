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

function getMatchPercentText(row) {
  if ('stub' in row) {
    return 'stub';
  }

  if ('effective' in row) {
    return '100.00%*';
  }

  return (row.matching * 100).toFixed(2) + '%';
}

// Helper for this set/remove attribute block
function setBooleanAttribute(element, attribute, value) {
  if (value) {
    element.setAttribute(attribute, '');
  } else {
    element.removeAttribute(attribute);
  }
}

//
// Global state
//

class ListingState {
  constructor() {
    this._query = '';
    this._sortCol = 'address';
    this._filterType = 1;
    this.sortDesc = false;
    this.hidePerfect = false;
    this.hideStub = false;
  }

  get filterType() {
    return parseInt(this._filterType);
  }

  set filterType(value) {
    value = parseInt(value);
    if (value >= 1 && value <= 3) {
      this._filterType = value;
    }
  }

  get query() {
    return this._query;
  }

  set query(value) {
    // Normalize search string
    this._query = value.toLowerCase().trim();
  }

  get sortCol() {
    return this._sortCol;
  }

  set sortCol(column) {
    if (column === this._sortCol) {
      this.sortDesc = !this.sortDesc;
    } else {
      this._sortCol = column;
    }
  }
}

const StateProxy = {
  set(obj, prop, value) {
    if (prop === 'onsort') {
      this._onsort = value;
      return true;
    }

    if (prop === 'onfilter') {
      this._onfilter = value;
      return true;
    }

    obj[prop] = value;

    if (prop === 'sortCol' || prop === 'sortDesc') {
      this._onsort();
    } else {
      this._onfilter();
    }
    return true;
  }
};

const appState = new Proxy(new ListingState(), StateProxy);

//
// Stateful functions
//

function addrShouldAppear(addr) {
  // Destructuring sets defaults for optional values from this object.
  const {
    effective = false,
    stub = false,
    diff = '',
    name,
    address,
    matching
  } = getDataByAddr(addr);

  if (appState.hidePerfect && (effective || matching >= 1)) {
    return false;
  }

  if (appState.hideStub && stub) {
    return false;
  }

  if (appState.query === '') {
    return true;
  }

  // Name/addr search
  if (appState.filterType === 1) {
    return (
      address.includes(appState.query) ||
      name.toLowerCase().includes(appState.query)
    );
  }

  // no diff for review.
  if (diff === '') {
    return false;
  }

  // special matcher for combined diff
  const anyLineMatch = ([addr, line]) => line.toLowerCase().trim().includes(appState.query);

  // Flatten all diff groups for the search
  const diffs = diff.map(([slug, subgroups]) => subgroups).flat();
  for (const subgroup of diffs) {
    const { both = [], orig = [], recomp = [] } = subgroup;

    // If search includes context
    if (appState.filterType === 2 && both.some(anyLineMatch)) {
      return true;
    }

    if (orig.some(anyLineMatch) || recomp.some(anyLineMatch)) {
      return true;
    }
  }

  return false;
}

// Row comparator function, using our chosen sort column and direction.
// -1 (A before B)
//  1 (B before A)
//  0 (equal)
function rowSortOrder(addrA, addrB) {
  const objA = getDataByAddr(addrA);
  const objB = getDataByAddr(addrB);
  const valA = objA[appState.sortCol];
  const valB = objB[appState.sortCol];

  if (valA > valB) {
    return appState.sortDesc ? -1 : 1;
  } else if (valA < valB) {
    return appState.sortDesc ? 1 : -1;
  }

  return 0;
}

//
// Custom elements
//

// Sets sort indicator arrow based on element attributes.
class SortIndicator extends window.HTMLElement {
  static observedAttributes = ['data-sort'];

  attributeChangedCallback(name, oldValue, newValue) {
    if (newValue === null) {
      this.textContent = '';
    } else {
      this.innerHTML = newValue === 'asc' ? '&#9650;' : '&#9660;';
    }
  }
}

class FuncRow extends window.HTMLElement {
  static observedAttributes = ['expanded'];

  constructor() {
    super();

    this.onclick = evt => (this.expanded = !this.expanded);
  }

  connectedCallback() {
    if (this.shadowRoot !== null) {
      return;
    }

    const template = document.querySelector('template#funcrow-template').content;
    const shadow = this.attachShadow({ mode: 'open' });
    shadow.appendChild(template.cloneNode(true));
  }

  get address() {
    return this.getAttribute('data-address');
  }

  get expanded() {
    return this.getAttribute('expanded') !== null;
  }

  set expanded(value) {
    setBooleanAttribute(this, 'expanded', value);
  }

  attributeChangedCallback(name, oldValue, newValue) {
    if (name !== 'expanded') {
      return;
    }

    if (this.onchangeExpand) {
      this.onchangeExpand(this.expanded);
    }
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

// Main application.
class ListingTable extends window.HTMLElement {
  constructor() {
    super();

    // Redraw the table on any changes.
    appState.onsort = () => this.sortRows();
    appState.onfilter = () => this.filterRows();

    const input = this.querySelector('input[type=search]');
    input.oninput = evt => (appState.query = evt.target.value);

    const hidePerf = this.querySelector('input#cbHidePerfect');
    hidePerf.onchange = evt => (appState.hidePerfect = evt.target.checked);
    hidePerf.checked = appState.hidePerfect;

    const hideStub = this.querySelector('input#cbHideStub');
    hideStub.onchange = evt => (appState.hideStub = evt.target.checked);
    hideStub.checked = appState.hideStub;

    this.querySelectorAll('input[name=filterType]').forEach(radio => {
      const checked = appState.filterType === parseInt(radio.getAttribute('value'));
      setBooleanAttribute(radio, 'checked', checked);

      radio.onchange = evt => (appState.filterType = radio.getAttribute('value'));
    });
  }

  setRowExpand(address, shouldExpand) {
    const tbody = this.querySelector('tbody');
    const funcrow = tbody.querySelector(`func-row[data-address="${address}"]`);
    if (funcrow === null) {
      return;
    }

    const existing = tbody.querySelector(`diff-row[data-address="${address}"]`);
    if (shouldExpand) {
      if (existing === null) {
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
    } else {
      if (existing !== null) {
        tbody.removeChild(existing);
      }
    }
  }

  connectedCallback() {
    const thead = this.querySelector('thead');
    const headers = thead.querySelectorAll('th');
    headers.forEach(th => {
      const col = th.getAttribute('data-col');
      if (col) {
        th.onclick = evt => (appState.sortCol = col);
      }
    });

    const tbody = this.querySelector('tbody');

    for (const obj of data) {
      const row = document.createElement('func-row');
      row.setAttribute('data-address', obj.address); // ?

      const items = [
        ['address', obj.address],
        ['name', obj.name],
        ['matching', getMatchPercentText(obj)]
      ];

      items.forEach(([slotName, content]) => {
        const div = document.createElement('div');
        div.setAttribute('slot', slotName);
        div.innerText = content;
        row.appendChild(div);
      });

      row.onchangeExpand = shouldExpand => this.setRowExpand(obj.address, shouldExpand);
      tbody.appendChild(row);
    }

    this.sortRows();
    this.filterRows();
  }

  sortRows() {
    const thead = this.querySelector('thead');
    const headers = thead.querySelectorAll('th');

    // Update sort indicator
    headers.forEach(th => {
      const col = th.getAttribute('data-col');
      const indicator = th.querySelector('sort-indicator');
      if (appState.sortCol === col) {
        indicator.setAttribute('data-sort', appState.sortDesc ? 'desc' : 'asc');
      } else {
        indicator.removeAttribute('data-sort');
      }
    });

    // Select only the function rows and the diff child row.
    // Exclude any nested tables used to *display* the diffs.
    const tbody = this.querySelector('tbody');
    const rows = tbody.querySelectorAll('func-row[data-address], diff-row[data-address]');

    // Sort all rows according to chosen order
    const newRows = Array.from(rows);
    newRows.sort((rowA, rowB) => {
      const addrA = rowA.getAttribute('data-address');
      const addrB = rowB.getAttribute('data-address');

      // Diff row always sorts after its parent row
      if (addrA === addrB && rowB.className === 'diffRow') {
        return -1;
      }

      return rowSortOrder(addrA, addrB);
    });

    // Replace existing rows with updated order
    newRows.forEach(row => tbody.appendChild(row));
  }

  filterRows() {
    const tbody = this.querySelector('tbody');
    const rows = tbody.querySelectorAll('func-row[data-address], diff-row[data-address]');

    rows.forEach(row => {
      const addr = row.getAttribute('data-address');
      const hidden = !addrShouldAppear(addr);
      setBooleanAttribute(row, 'hidden', hidden);
    });

    // Update row count
    this.querySelector('#rowcount').textContent = `${tbody.querySelectorAll('func-row:not([hidden])').length}`;
  }
}

window.onload = () => {
  window.customElements.define('listing-table', ListingTable);
  window.customElements.define('diff-display', DiffDisplay);
  window.customElements.define('diff-display-options', DiffDisplayOptions);
  window.customElements.define('sort-indicator', SortIndicator);
  window.customElements.define('func-row', FuncRow);
  window.customElements.define('diff-row', DiffRow);
  window.customElements.define('no-diff', NoDiffMessage);
};
