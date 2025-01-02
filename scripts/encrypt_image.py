import io
import os
import sys
import time
import base64
import asyncio
import gradio as gr

from pathlib import Path
from queue import Queue, Empty
from urllib.parse import unquote
from threading import Lock, Event, Thread
from concurrent.futures import ThreadPoolExecutor
from fastapi import FastAPI, Request, Response
from PIL import Image as PILImage, PngImagePlugin, _util, ImagePalette
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from modules import shared, script_callbacks, images
from modules.api import api
from modules.paths_internal import models_path

from scripts.encrypt_core import decrypt_image_v3, get_sha256, encrypt_image_v3

RST = '\033[0m'
ORG = '\033[38;5;208m'
AR = f'{ORG}▶{RST}'
BLUE = '\033[38;5;39m'
RED = '\033[38;5;196m'
TITLE = 'Image Encryption:'

emb_dir  = shared.cmd_opts.embeddings_dir
models = Path(models_path)

password = getattr(shared.cmd_opts, 'encrypt_pass', None)
image_extensions = ['.png', '.jpg', '.jpeg', '.gif', '.webp', '.avif']
image_keys = ['Encrypt', 'EncryptPwdSha']

def set_shared_options():
    section = ("encrypt_image_is_enable", "Encrypt image")
    option = shared.OptionInfo(default="Yes", label="Whether the encryption plug-in is enabled", section=section)
    option.do_not_save = True
    shared.opts.add_option("encrypt_image_is_enable", option)
    shared.opts.data['encrypt_image_is_enable'] = "Yes"

class EncryptedImage(PILImage.Image):
    __name__ = "EncryptedImage"

    @staticmethod
    def from_image(image: PILImage.Image):
        image = image.copy()
        img = EncryptedImage()
        img.im = image.im
        img._mode = image.mode
        if image.im.mode:
            try:
                img.mode = image.im.mode
            except Exception:
                pass

        img._size = image.size
        img.format = image.format
        if image.mode in ("P", "PA"):
            img.palette = image.palette.copy() if image.palette else ImagePalette.ImagePalette()

        img.info = image.info.copy()
        return img

    def save(self, fp, format=None, **params):
        filename = ""
        encryption_type = self.info.get('Encrypt')

        if isinstance(fp, Path):
            filename = str(fp)
        elif _util.is_path(fp):
            filename = fp
        elif fp == sys.stdout:
            try:
                fp = sys.stdout.buffer
            except AttributeError:
                pass

        if not filename and hasattr(fp, "name") and _util.is_path(fp.name):
            filename = fp.name

        if not filename or not password:
            super().save(fp, format=format, **params)
            return

        if encryption_type == 'pixel_shuffle_3':
            super().save(fp, format=format, **params)
            return

        back_img = PILImage.new('RGBA', self.size)
        back_img.paste(self)

        try:
            encrypted_img = PILImage.fromarray(encrypt_image_v3(self, get_sha256(password)))
            self.paste(encrypted_img)
            encrypted_img.close()
        except Exception as e:
            if "axes don't match array" in str(e):
                fn = Path(filename)
                os.system(f'rm -f {fn}')
                return

        self.format = PngImagePlugin.PngImageFile.format
        pnginfo = params.get('pnginfo', PngImagePlugin.PngInfo())
        if not pnginfo:
            pnginfo = PngImagePlugin.PngInfo()
            for key in (self.info or {}).keys():
                if self.info[key]:
                    print(f'{key}:{str(self.info[key])}')
                    pnginfo.add_text(key,str(self.info[key]))

        pnginfo.add_text('Encrypt', 'pixel_shuffle_3')
        pnginfo.add_text('EncryptPwdSha', get_sha256(f'{get_sha256(password)}Encrypt'))

        params.update(pnginfo=pnginfo)
        super().save(fp, format=self.format, **params)
        self.paste(back_img)
        back_img.close()

def open(fp, *args, **kwargs):
    try:
        if not _util.is_path(fp) or not Path(fp).suffix:
            return super_open(fp, *args, **kwargs)

        if isinstance(fp, bytes):
            return encode_pil_to_base64(fp)

        img = super_open(fp, *args, **kwargs)
        try:
            pnginfo = img.info or {}

            if password and img.format.lower() == PngImagePlugin.PngImageFile.format.lower():
                if pnginfo.get("Encrypt") == 'pixel_shuffle_3':
                    decrypted_img = PILImage.fromarray(decrypt_image_v3(img, get_sha256(password)))
                    img.paste(decrypted_img)
                    decrypted_img.close()
                    pnginfo["Encrypt"] = None

            return EncryptedImage.from_image(img)

        except Exception as e:
            print(f"Error in 146 : {fp} : {e}")
            return None

        finally:
            img.close()

    except Exception as e:
        print(f"Error in 153 : {fp} : {e}")
        return None

def encode_pil_to_base64(img: PILImage.Image):
    pnginfo = img.info or {}

    with io.BytesIO() as output_bytes:
        if pnginfo.get("Encrypt") == 'pixel_shuffle_3':
            img.paste(PILImage.fromarray(decrypt_image_v3(img, get_sha256(password))))

        pnginfo["Encrypt"] = None
        img.save(output_bytes, format=PngImagePlugin.PngImageFile.format, quality=shared.opts.jpeg_quality)
        bytes_data = output_bytes.getvalue()

    return base64.b64encode(bytes_data)

executor = ThreadPoolExecutor(max_workers=100)
semaphore = asyncio.Semaphore(min(os.cpu_count() * 2, 10))
p_cache = {}

def imgResize(image, target_height=500):
    width, height = image.size
    if height > target_height:
        aspect_ratio = width / height
        new_width = int(target_height * aspect_ratio)
        return image.resize((new_width, target_height), PILImage.Resampling.LANCZOS)
    return image

async def imgAsync(file_path, image_keys, should_resize=False):
    try:
        async with semaphore:
            if file_path in p_cache:
                return p_cache[file_path]

            loop = asyncio.get_event_loop()
            content = await loop.run_in_executor(
                executor,
                lambda: imgProcess(file_path, image_keys, should_resize)
            )

            p_cache[file_path] = content
            return content
    except Exception as e:
        print(f"Error in 196 : {file_path}: {e}")
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception as inner_e:
            print(f"Error in 201 : {inner_e}")
            return None
    finally:
        if file_path in p_cache:
            del p_cache[file_path]

def imgProcess(file_path, image_keys, should_resize):
    with PILImage.open(file_path) as image:
        if should_resize:
            image = imgResize(image)
            image.save(file_path)
            
        pnginfo = image.info or {}
        
        if not all(k in pnginfo for k in image_keys):
            try:
                EncryptedImage.from_image(image).save(file_path)
                image = PILImage.open(file_path)
                pnginfo = image.info or {}
            except Exception as e:
                print(f"Error in 221 : {file_path}: {e}")
                return None

        buffered = io.BytesIO()
        info = PngImagePlugin.PngInfo()

        for key, value in pnginfo.items():
            if value is None or key == 'icc_profile':
                continue
            if isinstance(value, bytes):
                try:
                    info.add_text(key, value.decode('utf-8'))
                except UnicodeDecodeError:
                    try:
                        info.add_text(key, value.decode('utf-16'))
                    except UnicodeDecodeError:
                        info.add_text(key, str(value))
                        print(f"Error decoding '{key}' in hook http. {file_path}")
            else:
                info.add_text(key, str(value))

        image.save(buffered, format=PngImagePlugin.PngImageFile.format, pnginfo=info)
        image.close()
        return buffered.getvalue()

def hook_http_request(app: FastAPI):
    @app.middleware("http")
    async def image_decrypting(req: Request, call_next):
        endpoint = '/' + req.scope.get('path', 'err').strip('/')

        def process_query(endpoint, prefixes, param):
            if endpoint.startswith(prefixes):
                query_string = unquote(req.scope.get('query_string', b'').decode('utf-8'))
                return next((sub.split('=')[1] for sub in query_string.split('&') if sub.startswith(param)), '')
            return None

        path = process_query(endpoint, ('/infinite_image_browsing/image-thumbnail', '/infinite_image_browsing/file'), 'path=')
        if path:
            endpoint = f'/file={path}'

        filename = process_query(endpoint, '/sd_extra_networks/thumb', 'filename=')
        if filename:
            endpoint = f'/file={filename}'

        if endpoint.startswith('/file='):
            file_path = Path(endpoint[6:])
            ext = file_path.suffix.lower().split('?')[0]

            if 'card-no-preview.png' in str(file_path):
                return await call_next(req)

            if ext in image_extensions:
                should_resize = str(models) in str(file_path) or str(emb_dir) in str(file_path)
                content = await imgAsync(file_path, image_keys, should_resize)
                if content:
                    return Response(content=content, media_type="image/png")
                return await call_next(req)

        return await call_next(req)

def WatchDogs(paths, extensions):
    OBS = Observer()
    file_queue = Queue(maxsize=1000)
    processed_files = set()
    lock = Lock()
    shutdown_event = Event()
    num_cpus = os.cpu_count()
    thread_pool = ThreadPoolExecutor(max_workers=num_cpus * 4)

    def process_queue():
        futures = []
        while not shutdown_event.is_set():
            try:
                fp = file_queue.get(timeout=0.1)
                if fp:
                    future = thread_pool.submit(process_file, fp)
                    futures.append(future)
                    futures = [f for f in futures if not f.done()]
                file_queue.task_done()
            except Empty:
                continue
            except Exception as e:
                print(f"Error in 303 : {e}")

    def process_file(fp):
        with lock:
            if fp in processed_files:
                return
            processed_files.add(fp)
        try:
            img = PILImage.open(fp)
            pnginfo = img.info or {}
            if not all(k in pnginfo for k in image_keys):
                print(f"{AR} {fp}")
                EncryptedImage.from_image(img).save(fp)
        except Exception as e:
            print(f"Error in 317 : {fp} : {e}")
            with lock:
                processed_files.discard(fp)

    class OBSHandler(FileSystemEventHandler):
        def __init__(self):
            super().__init__()
            self.event_buffer = {}
            self.last_processed = time.time()
            self.buffer_lock = Lock()

        def on_any_event(self, event):
            if event.is_directory:
                return
            fp = Path(event.src_path)
            if fp.suffix.lower() not in extensions:
                return
            if event.event_type in ('created', 'modified', 'moved'):
                with self.buffer_lock:
                    self.event_buffer[fp] = time.time()
                current_time = time.time()
                if current_time - self.last_processed > 0.1:
                    self._process_buffer()

        def _process_buffer(self):
            with self.buffer_lock:
                current_time = time.time()
                files_to_process = []
                for fp, timestamp in list(self.event_buffer.items()):
                    if current_time - timestamp >= 0.1 and fp.exists():
                        files_to_process.append(fp)
                        del self.event_buffer[fp]
                for fp in files_to_process:
                    file_queue.put(fp)
                self.last_processed = current_time

    num_workers = num_cpus * 4
    workers = []
    for _ in range(num_workers):
        worker = Thread(target=process_queue, daemon=True)
        worker.start()
        workers.append(worker)

    handler = OBSHandler()
    for path in paths:
        OBS.schedule(handler, path, recursive=True)
    OBS.start()

def app_started_callback(_: gr.Blocks, app: FastAPI):
    app.middleware_stack = None
    set_shared_options()
    hook_http_request(app)
    app.build_middleware_stack()

if PILImage.Image.__name__ != 'EncryptedImage':
    super_open = PILImage.open
    super_encode_pil_to_base64 = api.encode_pil_to_base64
    super_modules_images_save_image = images.save_image
    super_api_middleware = api.api_middleware

    if password is not None:
        PILImage.Image = EncryptedImage
        PILImage.open = open
        api.encode_pil_to_base64 = encode_pil_to_base64

    WatchDogs([models, emb_dir], set(image_extensions))
    print(f'{AR} {TITLE} \033[96mWatchdog\033[0m started')

if password == '':
    msg = f'{AR} {TITLE} {RED}Disabled{RST}, --encrypt-pass value is empty.'
elif not password:
    msg = f'{AR} {TITLE} {RED}Disabled{RST}, Missing --encrypt-pass command line argument.'
else:
    script_callbacks.on_app_started(app_started_callback)
    msg = f'{AR} {TITLE} {BLUE}Enabled{RST}, Encryption Level {ORG}5{RST}' \
          f'\n{AR} {TITLE} Check the release page for decrypting images in local Windows ' \
          f'https://github.com/gutris1/sd-encrypt-image'

print(msg)
