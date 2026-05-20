"""
Rich Text Handler — specialized injection for rich text editor frameworks.

Editors require framework-specific approaches to bypass client-side sanitization:
- TinyMCE: use source/code view mode to inject raw HTML bypassing WYSIWYG filter
- Quill: paste API with text/html MIME type to inject HTML delta
- CKEditor 4/5: setData() API bypasses editor sanitization; use source dialog
- Froala: html.set() API or HTML mode toggle
- Summernote: code() method or pasteHTML
- Draft.js / ProseMirror / Lexical: use contenteditable innerHTML as fallback

For each editor, we test both:
1. API-level injection (might be filtered server-side)
2. DOM-level injection (tests stored XSS if server doesn't sanitize)
"""
from __future__ import annotations

from dataclasses import dataclass

from playwright.async_api import Page

from shared.logger import audit

TOOL = "rich_text_handler"


@dataclass
class RichTextResult:
    editor_type:      str
    injection_method: str    # api|clipboard|dom|source_mode
    payload:          str
    injected:         bool
    raw_html_used:    bool   # did we bypass WYSIWYG filter?
    error:            str = ""


class RichTextHandler:
    def __init__(self, page: Page):
        self.page = page

    async def inject(self, surface: dict, payload: str) -> RichTextResult:
        editor_type = surface.get("editor_type", "contenteditable")
        name = surface.get("name", "")
        selector = surface.get("selector", "")

        handlers = {
            "tinymce":       self._inject_tinymce,
            "quill":         self._inject_quill,
            "ckeditor4":     self._inject_ckeditor4,
            "ckeditor5":     self._inject_ckeditor5,
            "froala":        self._inject_froala,
            "summernote":    self._inject_summernote,
            "contenteditable": self._inject_contenteditable,
        }

        handler = handlers.get(editor_type, self._inject_contenteditable)
        try:
            result = await handler(name, selector, payload)
            audit.tool_call(TOOL, "inject", {
                "editor": editor_type,
                "method": result.injection_method,
                "injected": result.injected,
            })
            return result
        except Exception as e:
            return RichTextResult(editor_type, "error", payload, False, False, str(e))

    async def _inject_tinymce(self, editor_id: str, selector: str, payload: str) -> RichTextResult:
        # Method 1: Use source code view (bypasses TinyMCE WYSIWYG sanitization)
        source_ok = await self.page.evaluate(f"""
        () => {{
            const ed = window.tinymce && window.tinymce.get({repr(editor_id)});
            if (!ed) return false;
            try {{
                // Open source code dialog if available
                ed.execCommand('mceCodeEditor');
                // In source mode, setContent injects raw HTML
                ed.setContent({repr(payload)});
                return true;
            }} catch(e) {{
                return false;
            }}
        }}
        """)
        if source_ok:
            return RichTextResult("tinymce", "source_mode", payload, True, True)

        # Method 2: Direct API (may be sanitized)
        api_ok = await self.page.evaluate(f"""
        () => {{
            const ed = window.tinymce && window.tinymce.get({repr(editor_id)});
            if (!ed) return false;
            ed.setContent({repr(payload)});
            return true;
        }}
        """)
        return RichTextResult("tinymce", "api", payload, bool(api_ok), False)

    async def _inject_quill(self, editor_id: str, selector: str, payload: str) -> RichTextResult:
        # Method 1: Clipboard API with text/html — Quill processes pasted HTML
        clip_ok = await self.page.evaluate(f"""
        async () => {{
            const el = document.querySelector({repr(selector)});
            if (!el) return false;
            el.focus();
            // Select all existing content
            document.execCommand('selectAll');
            // Paste HTML via ClipboardEvent
            const dt = new DataTransfer();
            dt.setData('text/html', {repr(payload)});
            dt.setData('text/plain', 'test');
            const event = new ClipboardEvent('paste', {{
                clipboardData: dt,
                bubbles: true,
                cancelable: true,
            }});
            el.dispatchEvent(event);
            return true;
        }}
        """)
        if clip_ok:
            return RichTextResult("quill", "clipboard", payload, True, True)

        # Method 2: Direct innerHTML (bypasses Quill delta model)
        dom_ok = await self.page.evaluate(f"""
        () => {{
            const el = document.querySelector({repr(selector)});
            if (!el) return false;
            el.innerHTML = {repr(payload)};
            el.dispatchEvent(new Event('input', {{bubbles: true}}));
            return true;
        }}
        """)
        return RichTextResult("quill", "dom", payload, bool(dom_ok), True)

    async def _inject_ckeditor4(self, instance_name: str, selector: str, payload: str) -> RichTextResult:
        # setData() is the official API — bypasses WYSIWYG but server may sanitize
        api_ok = await self.page.evaluate(f"""
        () => {{
            const ed = window.CKEDITOR && window.CKEDITOR.instances[{repr(instance_name)}];
            if (!ed) return false;
            ed.setData({repr(payload)});
            return true;
        }}
        """)
        if api_ok:
            return RichTextResult("ckeditor4", "api", payload, True, False)

        # Source dialog mode
        source_ok = await self.page.evaluate(f"""
        () => {{
            const ed = window.CKEDITOR && window.CKEDITOR.instances[{repr(instance_name)}];
            if (!ed) return false;
            try {{
                ed.execCommand('source');
                const body = ed.document.getBody().$;
                body.value = {repr(payload)};
                ed.execCommand('source');
                return true;
            }} catch(e) {{ return false; }}
        }}
        """)
        return RichTextResult("ckeditor4", "source_mode", payload, bool(source_ok), True)

    async def _inject_ckeditor5(self, editor_id: str, selector: str, payload: str) -> RichTextResult:
        # CKEditor 5 stores instance in DOM element
        api_ok = await self.page.evaluate(f"""
        () => {{
            const el = document.querySelector({repr(selector)});
            if (!el) return false;
            // CKEditor 5 attaches instance to __ckeditorInstance or ckeditorInstance
            const ed = el.ckeditorInstance || el.__ckeditorInstance ||
                       (window.ckeditorInstances && window.ckeditorInstances[0]);
            if (!ed) return false;
            try {{
                ed.setData({repr(payload)});
                return true;
            }} catch(e) {{
                el.innerHTML = {repr(payload)};
                return true;
            }}
        }}
        """)
        return RichTextResult("ckeditor5", "api", payload, bool(api_ok), False)

    async def _inject_froala(self, editor_id: str, selector: str, payload: str) -> RichTextResult:
        api_ok = await self.page.evaluate(f"""
        () => {{
            const el = document.querySelector('.fr-element') ||
                       document.querySelector({repr(selector)});
            if (!el) return false;
            // Froala stores instance on parent element
            const parent = el.closest('.fr-wrapper') || el.parentElement;
            const froalaData = parent && parent['data-froala.editor'];
            if (froalaData) {{
                froalaData.html.set({repr(payload)});
                return true;
            }}
            // Fallback: direct innerHTML
            el.innerHTML = {repr(payload)};
            return true;
        }}
        """)
        return RichTextResult("froala", "api", payload, bool(api_ok), False)

    async def _inject_summernote(self, editor_id: str, selector: str, payload: str) -> RichTextResult:
        # Summernote jQuery plugin — use code() method
        api_ok = await self.page.evaluate(f"""
        () => {{
            if (window.jQuery) {{
                const el = jQuery({repr(selector)});
                if (el.length && el.summernote) {{
                    el.summernote('code', {repr(payload)});
                    return true;
                }}
            }}
            const el = document.querySelector('.note-editable') ||
                       document.querySelector({repr(selector)});
            if (!el) return false;
            el.innerHTML = {repr(payload)};
            return true;
        }}
        """)
        return RichTextResult("summernote", "api", payload, bool(api_ok), False)

    async def _inject_contenteditable(self, editor_id: str, selector: str, payload: str) -> RichTextResult:
        ok = await self.page.evaluate(f"""
        () => {{
            const el = document.querySelector({repr(selector)});
            if (!el) return false;
            el.focus();
            // execCommand insertHTML — triggers input event handlers
            const result = document.execCommand('insertHTML', false, {repr(payload)});
            if (!result) {{
                el.innerHTML = {repr(payload)};
            }}
            el.dispatchEvent(new Event('input', {{bubbles: true}}));
            el.dispatchEvent(new Event('change', {{bubbles: true}}));
            return true;
        }}
        """)
        return RichTextResult("contenteditable", "dom", payload, bool(ok), True)
