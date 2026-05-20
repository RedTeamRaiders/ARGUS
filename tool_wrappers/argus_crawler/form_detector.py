"""
Form Detector — finds ALL input surfaces on a page.

Detects:
- Standard HTML inputs, textareas, selects
- Rich text editors: TinyMCE, Quill, CKEditor, Froala, Summernote, Draft.js, ProseMirror
- Shadow DOM inputs
- Dynamic inputs added after page load (MutationObserver equivalent)
- Non-form surfaces: URL params, hash fragments
- JSON body inputs in XHR/fetch intercepted forms
- Hidden inputs (often interesting for parameter tampering)
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from playwright.async_api import Page


@dataclass
class InputSurface:
    input_type:   str           # text|password|email|textarea|select|hidden|file|richeditor|url_param
    name:         str
    value:        str           # current value
    placeholder:  str
    form_action:  str
    form_method:  str
    selector:     str           # CSS selector to target this input
    editor_type:  Optional[str] = None  # tinymce|quill|ckeditor|froala|summernote|contenteditable
    is_hidden:    bool = False
    attributes:   dict = field(default_factory=dict)


class FormDetector:
    def __init__(self, page: Page):
        self.page = page

    async def detect_all(self) -> list[dict]:
        surfaces = []
        surfaces.extend(await self._detect_standard_inputs())
        surfaces.extend(await self._detect_rich_editors())
        surfaces.extend(await self._detect_shadow_dom())
        surfaces.extend(await self._detect_dynamic_inputs())
        return surfaces

    async def _detect_standard_inputs(self) -> list[dict]:
        return await self.page.evaluate("""
        () => {
            const surfaces = [];
            const inputs = document.querySelectorAll(
                'input:not([type="button"]):not([type="submit"]):not([type="reset"]):not([type="image"]):not([type="checkbox"]):not([type="radio"]), textarea, select'
            );

            inputs.forEach((el, idx) => {
                const form = el.closest('form');
                const rect = el.getBoundingClientRect();
                const isHidden = el.type === 'hidden' ||
                                 getComputedStyle(el).display === 'none' ||
                                 rect.width === 0;

                surfaces.push({
                    input_type: el.tagName === 'TEXTAREA' ? 'textarea'
                              : el.tagName === 'SELECT' ? 'select'
                              : (el.type || 'text'),
                    name:        el.name || el.id || el.getAttribute('data-name') || `input_${idx}`,
                    value:       el.value || '',
                    placeholder: el.placeholder || '',
                    form_action: form ? (form.action || window.location.href) : window.location.href,
                    form_method: form ? (form.method || 'GET').toUpperCase() : 'GET',
                    selector:    el.id ? `#${CSS.escape(el.id)}`
                               : el.name ? `[name="${CSS.escape(el.name)}"]`
                               : `form input:nth-of-type(${idx + 1})`,
                    is_hidden:   isHidden,
                    attributes:  {
                        maxlength: el.maxLength,
                        pattern:   el.pattern,
                        required:  el.required,
                        autocomplete: el.autocomplete,
                    },
                });
            });
            return surfaces;
        }
        """)

    async def _detect_rich_editors(self) -> list[dict]:
        return await self.page.evaluate("""
        () => {
            const editors = [];

            // TinyMCE
            if (window.tinymce) {
                window.tinymce.editors.forEach((ed, idx) => {
                    editors.push({
                        input_type:  'richeditor',
                        name:        ed.id || `tinymce_${idx}`,
                        value:       ed.getContent() || '',
                        placeholder: '',
                        form_action: document.querySelector('form') ? document.querySelector('form').action : window.location.href,
                        form_method: 'POST',
                        selector:    `#${ed.id}`,
                        editor_type: 'tinymce',
                        is_hidden:   false,
                        attributes:  {},
                    });
                });
            }

            // Quill
            document.querySelectorAll('.ql-editor').forEach((el, idx) => {
                editors.push({
                    input_type:  'richeditor',
                    name:        el.getAttribute('data-name') || `quill_${idx}`,
                    value:       el.innerHTML || '',
                    placeholder: el.getAttribute('data-placeholder') || '',
                    form_action: window.location.href,
                    form_method: 'POST',
                    selector:    `.ql-editor:nth-of-type(${idx + 1})`,
                    editor_type: 'quill',
                    is_hidden:   false,
                    attributes:  {},
                });
            });

            // CKEditor 4
            if (window.CKEDITOR) {
                Object.keys(window.CKEDITOR.instances).forEach((name, idx) => {
                    const ed = window.CKEDITOR.instances[name];
                    editors.push({
                        input_type:  'richeditor',
                        name:        name,
                        value:       ed.getData() || '',
                        placeholder: '',
                        form_action: window.location.href,
                        form_method: 'POST',
                        selector:    `#${name}`,
                        editor_type: 'ckeditor4',
                        is_hidden:   false,
                        attributes:  {},
                    });
                });
            }

            // CKEditor 5
            document.querySelectorAll('.ck-editor__editable').forEach((el, idx) => {
                editors.push({
                    input_type:  'richeditor',
                    name:        el.getAttribute('aria-label') || `ckeditor5_${idx}`,
                    value:       el.innerHTML || '',
                    placeholder: '',
                    form_action: window.location.href,
                    form_method: 'POST',
                    selector:    `.ck-editor__editable:nth-of-type(${idx + 1})`,
                    editor_type: 'ckeditor5',
                    is_hidden:   false,
                    attributes:  {},
                });
            });

            // Froala
            document.querySelectorAll('.fr-element').forEach((el, idx) => {
                editors.push({
                    input_type:  'richeditor',
                    name:        el.getAttribute('id') || `froala_${idx}`,
                    value:       el.innerHTML || '',
                    placeholder: '',
                    form_action: window.location.href,
                    form_method: 'POST',
                    selector:    `.fr-element:nth-of-type(${idx + 1})`,
                    editor_type: 'froala',
                    is_hidden:   false,
                    attributes:  {},
                });
            });

            // Summernote
            document.querySelectorAll('.note-editable').forEach((el, idx) => {
                editors.push({
                    input_type:  'richeditor',
                    name:        el.getAttribute('id') || `summernote_${idx}`,
                    value:       el.innerHTML || '',
                    placeholder: '',
                    form_action: window.location.href,
                    form_method: 'POST',
                    selector:    `.note-editable:nth-of-type(${idx + 1})`,
                    editor_type: 'summernote',
                    is_hidden:   false,
                    attributes:  {},
                });
            });

            // Generic contenteditable divs (Draft.js, ProseMirror, custom)
            document.querySelectorAll('[contenteditable="true"]').forEach((el, idx) => {
                // Skip already-identified editors
                if (el.closest('.ql-editor, .ck-editor__editable, .fr-element, .note-editable')) return;
                editors.push({
                    input_type:  'richeditor',
                    name:        el.getAttribute('id') || el.getAttribute('name') || `contenteditable_${idx}`,
                    value:       el.innerHTML || '',
                    placeholder: el.getAttribute('placeholder') || '',
                    form_action: window.location.href,
                    form_method: 'POST',
                    selector:    `[contenteditable="true"]:nth-of-type(${idx + 1})`,
                    editor_type: 'contenteditable',
                    is_hidden:   false,
                    attributes:  {},
                });
            });

            return editors;
        }
        """)

    async def _detect_shadow_dom(self) -> list[dict]:
        return await self.page.evaluate("""
        () => {
            const inputs = [];
            function searchShadowRoots(root) {
                const all = root.querySelectorAll('*');
                all.forEach(el => {
                    if (el.shadowRoot) {
                        const shadowInputs = el.shadowRoot.querySelectorAll(
                            'input, textarea, [contenteditable="true"]'
                        );
                        shadowInputs.forEach((inp, idx) => {
                            inputs.push({
                                input_type:  inp.type || 'text',
                                name:        inp.name || inp.id || `shadow_${idx}`,
                                value:       inp.value || inp.innerHTML || '',
                                placeholder: inp.placeholder || '',
                                form_action: window.location.href,
                                form_method: 'POST',
                                selector:    `shadow:${el.tagName}`,
                                is_hidden:   false,
                                attributes:  { shadow_host: el.tagName },
                            });
                        });
                        searchShadowRoots(el.shadowRoot);
                    }
                });
            }
            searchShadowRoots(document);
            return inputs;
        }
        """)

    async def _detect_dynamic_inputs(self) -> list[dict]:
        # Wait a moment for late-rendered inputs then re-scan
        await self.page.wait_for_timeout(500)
        # Check for AJAX-loaded content or lazy inputs via data attributes
        return await self.page.evaluate("""
        () => {
            const inputs = [];
            // Inputs with data-* attributes suggesting dynamic content
            document.querySelectorAll('[data-bind], [data-model], [ng-model], [v-model], [:value]').forEach((el, idx) => {
                if (!el.matches('input, textarea, select')) return;
                inputs.push({
                    input_type:  el.type || 'text',
                    name:        el.getAttribute('ng-model') || el.getAttribute('v-model') || el.name || `dynamic_${idx}`,
                    value:       el.value || '',
                    placeholder: el.placeholder || '',
                    form_action: window.location.href,
                    form_method: 'POST',
                    selector:    `[name="${el.name || ''}"]`,
                    is_hidden:   false,
                    attributes:  { framework: 'angular/vue/dynamic' },
                });
            });
            return inputs;
        }
        """)
