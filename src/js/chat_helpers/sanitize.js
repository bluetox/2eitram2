export const strictConfig = {
    ALLOWED_TAGS: [
      'h1','h2','h3','h4','h5','h6',
      'p','div','span','pre','code','blockquote',
      'ul','ol','li','dl','dt','dd',
      'img','a','table','thead','tbody','tfoot','tr','th','td',
      'br','hr','strong','em','u','s','sub','sup',
      'small','big','figure','figcaption'
    ],
  
    ALLOWED_ATTR: [
      'href','title','alt','src','srcset','width','height',
      'colspan','rowspan','align','valign',
      'class','style','name'
    ],

    FORBID_ATTR: [/^on/i, 'id'],
  
    ALLOWED_CSS_PROPERTIES: [
      'color','background-color','font-size','font-weight','font-style',
      'text-decoration','text-align','margin','padding','border',
      'width','height','max-width','max-height'
    ],
  
    ALLOWED_URI_REGEXP: /^(?:[#\/][^"\s]*)|(?:data:image\/[a-zA-Z0-9+\/=;,%\-_.]+)$/,

    WHOLE_DOCUMENT: false,
    SAFE_FOR_TEMPLATES: true
};

export function isHTML(str) {
    const doc = new DOMParser().parseFromString(str, "text/html");
    return Array.from(doc.body.childNodes).some((node) => node.nodeType === 1);
}

export function decodeHTMLEntities(html) {
    const txt = document.createElement("textarea");
    txt.innerHTML = DOMPurify.sanitize(html, strictConfig);
    return txt.value;
  }
  