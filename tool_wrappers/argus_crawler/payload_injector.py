"""
Payload Injector — fills input surfaces with payloads and submits.

Handles:
- Standard inputs: type, clear, fill
- Rich text editors: TinyMCE (setContent/sourceMode), Quill (clipboard API),
  CKEditor 4/5 (setData/internal API), contenteditable (execCommand/innerHTML)
- File inputs: create Blob/File with payload
- Select elements: inject option with payload value
- Hidden inputs: direct value override
- Form submission: handles both submit buttons and programmatic submit
"""
from __future__ import annotations

import asyncio
from dataclasses import dataclass

from playwright.async_api import Page


@dataclass
class InjectionResult:
    surface_name: str
    editor_type:  str
    payload:      str
    injected:     bool
    submitted:    bool
    error:        str = ""


class PayloadInjector:
    def __init__(self, page: Page):
        self.page = page

    async def inject(self, surface: dict, payload: str) -> InjectionResult:
        editor_type = surface.get("editor_type") or surface.get("input_type", "text")
        name = surface.get("name", "unknown")

        try:
            if surface.get("input_type") == "richeditor":
                injected = await self._inject_rich_editor(surface, payload)
            elif surface.get("input_type") == "hidden":
                injected = await self._inject_hidden(surface, payload)
            elif surface.get("input_type") == "file":
                injected = await self._inject_file(surface, payload)
            elif surface.get("input_type") == "select":
                injected = await self._inject_select(surface, payload)
            else:
                injected = await self._inject_standard(surface, payload)

            if not injected:
                return InjectionResult(name, editor_type, payload, False, False, "injection failed")

            submitted = await self._submit(surface)
            return InjectionResult(name, editor_type, payload, True, submitted)

        except Exception as e:
            return InjectionResult(name, editor_type, payload, False, False, str(e))

    async def _inject_standard(self, surface: dict, payload: str) -> bool:
        selector = surface.get("selector", "")
        if not selector:
            return False
        try:
            await self.page.click(selector, timeout=3000)
            await self.page.fill(selector, payload, timeout=3000)
            return True
        except Exception:
            # Try evaluate as fallback
            try:
                await self.page.evaluate(
                    f"() => {{ const el = document.querySelector({repr(selector)}); if(el) {{ el.value = {repr(payload)}; el.dispatchEvent(new Event('input', {{bubbles:true}})); }} }}"
                )
                return True
            except Exception:
                return False

    async def _inject_rich_editor(self, surface: dict, payload: str) -> bool:
        editor_type = surface.get("editor_type", "contenteditable")
        selector = surface.get("selector", "")
        name = surface.get("name", "")

        if editor_type == "tinymce":
            return await self._inject_tinymce(name, payload)
        elif editor_type == "quill":
            return await self._inject_quill(selector, payload)
        elif editor_type == "ckeditor4":
            return await self._inject_ckeditor4(name, payload)
        elif editor_type in ("ckeditor5", "froala", "summernote", "contenteditable"):
            return await self._inject_contenteditable(selector, payload)
        return False

    async def _inject_tinymce(self, editor_id: str, payload: str) -> bool:
        try:
            result = await self.page.evaluate(f"""
            () => {{
                const ed = window.tinymce && window.tinymce.get({repr(editor_id)});
                if (!ed) return false;
                // Try source mode first to bypass client-side sanitization
                if (ed.plugins.code) {{
                    ed.execCommand('mceCodeEditor');
                }}
                ed.setContent({repr(payload)});
                return true;
            }}
            """)
            return bool(result)
        except Exception:
            return False

    async def _inject_quill(self, selector: str, payload: str) -> bool:
        try:
            await self.page.evaluate(f"""
            () => {{
                const el = document.querySelector({repr(selector)});
                if (!el) return false;
                // Use clipboard API to inject HTML
                el.focus();
                const dt = new DataTransfer();
                dt.setData('text/html', {repr(payload)});
                dt.setData('text/plain', {repr(payload)});
                el.dispatchEvent(new ClipboardEvent('paste', {{clipboardData: dt, bubbles: true}}));
            }}
            """)
            return True
        except Exception:
            # Fallback: direct innerHTML
            try:
                await self.page.evaluate(f"""
                () => {{
                    const el = document.querySelector({repr(selector)});
                    if (el) {{ el.innerHTML = {repr(payload)}; }}
                }}
                """)
                return True
            except Exception:
                return False

    async def _inject_ckeditor4(self, instance_name: str, payload: str) -> bool:
        try:
            result = await self.page.evaluate(f"""
            () => {{
                const ed = window.CKEDITOR && window.CKEDITOR.instances[{repr(instance_name)}];
                if (!ed) return false;
                ed.setData({repr(payload)});
                return true;
            }}
            """)
            return bool(result)
        except Exception:
            return False

    async def _inject_contenteditable(self, selector: str, payload: str) -> bool:
        try:
            await self.page.evaluate(f"""
            () => {{
                const el = document.querySelector({repr(selector)});
                if (!el) return;
                el.focus();
                document.execCommand('selectAll', false, null);
                document.execCommand('insertHTML', false, {repr(payload)});
            }}
            """)
            return True
        except Exception:
            try:
                await self.page.evaluate(f"""
                () => {{
                    const el = document.querySelector({repr(selector)});
                    if (el) el.innerHTML = {repr(payload)};
                }}
                """)
                return True
            except Exception:
                return False

    async def _inject_hidden(self, surface: dict, payload: str) -> bool:
        selector = surface.get("selector", "")
        try:
            await self.page.evaluate(f"""
            () => {{
                const el = document.querySelector({repr(selector)});
                if (el) el.value = {repr(payload)};
            }}
            """)
            return True
        except Exception:
            return False

    async def _inject_file(self, surface: dict, payload: str) -> bool:
        selector = surface.get("selector", "")
        try:
            # Create a file with the payload content
            await self.page.evaluate(f"""
            async () => {{
                const el = document.querySelector({repr(selector)});
                if (!el) return;
                const blob = new Blob([{repr(payload)}], {{type: 'text/html'}});
                const file = new File([blob], 'argus_payload.html', {{type: 'text/html'}});
                const dt = new DataTransfer();
                dt.items.add(file);
                el.files = dt.files;
                el.dispatchEvent(new Event('change', {{bubbles: true}}));
            }}
            """)
            return True
        except Exception:
            return False

    async def _inject_select(self, surface: dict, payload: str) -> bool:
        selector = surface.get("selector", "")
        try:
            await self.page.evaluate(f"""
            () => {{
                const el = document.querySelector({repr(selector)});
                if (!el) return;
                const opt = document.createElement('option');
                opt.value = {repr(payload)};
                opt.text = {repr(payload)};
                el.appendChild(opt);
                el.value = {repr(payload)};
                el.dispatchEvent(new Event('change', {{bubbles: true}}));
            }}
            """)
            return True
        except Exception:
            return False

    async def _submit(self, surface: dict) -> bool:
        try:
            form_action = surface.get("form_action", "")
            # Try clicking submit button
            submitted = await self.page.evaluate("""
            () => {
                const btn = document.querySelector(
                    'button[type="submit"], input[type="submit"], button:not([type]), [role="button"]'
                );
                if (btn) { btn.click(); return true; }
                const form = document.querySelector('form');
                if (form) { form.submit(); return true; }
                return false;
            }
            """)
            if submitted:
                await self.page.wait_for_timeout(800)
            return bool(submitted)
        except Exception:
            return False
