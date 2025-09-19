#!/bin/bash
# Script untuk install dan setup bot Telegram VPS Admin

set -e

# Warna untuk output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variabel
BOT_DIR="/opt/vps-admin-bot"
SERVICE_NAME="vps-admin-bot"
PYTHON_FILE="vps_admin_bot.py"
CONFIG_FILE="bot_config.json"
LOG_FILE="/var/log/vps-admin-bot.log"

# Fungsi untuk print dengan warna
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Fungsi untuk cek apakah user adalah root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "Script ini harus dijalankan sebagai root!"
        echo "Gunakan: sudo $0"
        exit 1
    fi
}

# Fungsi untuk install dependencies
install_dependencies() {
    print_info "Installing dependencies..."
    
    # Update package list
    apt update -y
    
    # Install Python3 dan pip jika belum ada
    apt install -y python3 python3-pip python3-venv curl wget
    
    # Install systemd jika belum ada
    apt install -y systemd
    
    # Install speedtest-cli
    pip3 install speedtest-cli --break-system-packages
    
    print_success "Dependencies installed successfully"
}

# Fungsi untuk membuat directory dan virtual environment
setup_environment() {
    print_info "Setting up environment..."
    
    # Buat directory untuk bot
    mkdir -p $BOT_DIR
    cd $BOT_DIR
    
    # Buat virtual environment
    python3 -m venv venv
    source venv/bin/activate
    
    # Install Python packages
    pip install python-telegram-bot==20.7 psutil requests --break-system-packages
    
    # Buat log file
    touch $LOG_FILE
    chmod 666 $LOG_FILE
    
    print_success "Environment setup completed"
}

# Fungsi untuk membuat file bot Python yang diperbaiki
create_bot_file() {
    print_info "Creating bot file..."
    
    cat > $BOT_DIR/$PYTHON_FILE << 'EOF'
#!/usr/bin/env python3
"""
VPS Admin Telegram Bot - Fixed Version
Bot untuk administrasi VPS melalui Telegram
"""

import os
import subprocess
import logging
import asyncio
import json
import shlex
from telegram import Update, InlineKeyboardButton, InlineKeyboardMarkup
from telegram.ext import Application, CommandHandler, CallbackQueryHandler, MessageHandler, filters, ContextTypes
import psutil
from datetime import datetime

# Load konfigurasi
def load_config():
    try:
        with open('/opt/vps-admin-bot/bot_config.json', 'r') as f:
            return json.load(f)
    except Exception as e:
        logging.error(f"Error loading config: {e}")
        return {"bot_token": "", "admin_chat_ids": []}

config = load_config()
BOT_TOKEN = config.get("bot_token", "")
ADMIN_CHAT_IDS = config.get("admin_chat_ids", [])

# Setup logging
logging.basicConfig(
    filename='/var/log/vps-admin-bot.log',
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    level=logging.INFO
)
logger = logging.getLogger(__name__)

# Juga log ke console
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

class VPSAdminBot:
    def __init__(self):
        self.waiting_for_password = set()
        self.waiting_for_command = set()
        
    def is_admin(self, chat_id):
        """Cek apakah user adalah admin"""
        return int(chat_id) in [int(admin_id) for admin_id in ADMIN_CHAT_IDS]
    
    async def run_command(self, command, timeout=30):
        """Menjalankan command shell dengan aman dan non-blocking"""
        try:
            if any(dangerous in command.lower() for dangerous in ['rm -rf /', 'dd if=', 'mkfs', 'fdisk']):
                return "", "❌ Command berbahaya tidak diizinkan", 1
            
            logger.info(f"Executing command: {command}")
            
            proc = await asyncio.create_subprocess_shell(
                command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                stdout_str = stdout.decode('utf-8', errors='ignore').strip()
                stderr_str = stderr.decode('utf-8', errors='ignore').strip()
                
                if stdout_str:
                    logger.info(f"Command stdout: {stdout_str[:200]}...")
                if stderr_str:
                    logger.warning(f"Command stderr: {stderr_str[:200]}...")
                    
                return stdout_str, stderr_str, proc.returncode
                
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()
                logger.warning(f"Command timeout (>{timeout}s): {command}")
                return "", f"❌ Command timeout (>{timeout}s)", -1
                
        except Exception as e:
            logger.error(f"Error executing command '{command}': {e}")
            return "", f"❌ Error: {str(e)}", -1

    def _get_main_menu_keyboard(self):
        """Returns the InlineKeyboardMarkup for the main menu."""
        keyboard = [
            [InlineKeyboardButton("📊 System Info", callback_data='sysinfo')],
            [InlineKeyboardButton("🔄 Reboot Server", callback_data='reboot')],
            [InlineKeyboardButton("🔐 Change Root Password", callback_data='change_pass')],
            [InlineKeyboardButton("🌐 Speedtest", callback_data='speedtest')],
            [InlineKeyboardButton("💾 Disk Usage", callback_data='disk_usage')],
            [InlineKeyboardButton("📈 Resource Monitor", callback_data='resources')],
            [InlineKeyboardButton("🔧 Services Status", callback_data='services')],
            [InlineKeyboardButton("📋 Running Processes", callback_data='processes')],
            [InlineKeyboardButton("⚡ Custom Command", callback_data='custom_cmd')]
        ]
        return InlineKeyboardMarkup(keyboard)

    def _get_back_button(self):
        """Returns an InlineKeyboardMarkup with a back button."""
        keyboard = [
            [InlineKeyboardButton("⬅️ Kembali ke Menu", callback_data='main_menu')]
        ]
        return InlineKeyboardMarkup(keyboard)

    async def _send_main_menu(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Sends the main menu, editing the message if it's from a callback query."""
        text = (
            "🖥️ *VPS Admin Panel*\n\n"
            "Selamat datang di panel administrasi VPS!\n"
            "Pilih aksi yang ingin dilakukan:"
        )
        reply_markup = self._get_main_menu_keyboard()
        
        # Check if the update is from a callback query (button press)
        if update.callback_query:
            await update.callback_query.edit_message_text(
                text,
                parse_mode='Markdown',
                reply_markup=reply_markup
            )
        # Otherwise, it's a command, so reply with a new message
        else:
            await update.message.reply_text(
                text,
                parse_mode='Markdown',
                reply_markup=reply_markup
            )

    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Command /start"""
        chat_id = update.effective_chat.id
        if not self.is_admin(chat_id):
            await update.message.reply_text("❌ Akses ditolak. Anda bukan admin.")
            logger.warning(f"Unauthorized access attempt from chat_id: {chat_id}")
            return
        
        await self._send_main_menu(update, context)

    async def button_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk inline keyboard"""
        query = update.callback_query
        await query.answer()
        
        user_id = query.from_user.id
        if not self.is_admin(user_id):
            await query.edit_message_text("❌ Akses ditolak.")
            return
            
        try:
            if query.data == 'sysinfo':
                await self.system_info(query)
            elif query.data == 'reboot':
                await self.reboot_server(query)
            elif query.data == 'change_pass':
                await self.change_password_prompt(query)
            elif query.data == 'speedtest':
                await self.speedtest(query)
            elif query.data == 'disk_usage':
                await self.disk_usage(query)
            elif query.data == 'resources':
                await self.resource_monitor(query)
            elif query.data == 'services':
                await self.services_status(query)
            elif query.data == 'processes':
                await self.running_processes(query)
            elif query.data == 'custom_cmd':
                await self.custom_command_prompt(query)
            elif query.data == 'main_menu':
                user_id = query.from_user.id
                self.waiting_for_password.discard(user_id)
                self.waiting_for_command.discard(user_id)
                await self._send_main_menu(update, context)
            elif query.data == 'confirm_reboot':
                await query.edit_message_text("🔄 Server sedang direboot... Bot akan offline sementara.")
                await self.run_command("sleep 2 && sudo reboot")
            elif query.data == 'cancel':
                user_id = query.from_user.id
                self.waiting_for_password.discard(user_id)
                self.waiting_for_command.discard(user_id)
                await query.edit_message_text("❌ Operasi dibatalkan.", reply_markup=self._get_back_button())
        except Exception as e:
            logger.error(f"Error in button handler: {e}")
            await query.edit_message_text(f"❌ Error: {str(e)}")

    async def system_info(self, query):
        """Menampilkan informasi sistem"""
        try:
            await query.edit_message_text("📊 Mengambil informasi sistem...")
            
            # Jalankan command secara paralel
            uptime_task = self.run_command("uptime")
            os_info_task = self.run_command("lsb_release -d 2>/dev/null || cat /etc/os-release | grep PRETTY_NAME | cut -d'=' -f2 | tr -d '\"'")
            kernel_info_task = self.run_command("uname -r")
            
            # Jalankan psutil calls di thread terpisah
            cpu_percent_task = asyncio.to_thread(psutil.cpu_percent, interval=1)
            virtual_memory_task = asyncio.to_thread(psutil.virtual_memory)
            disk_usage_task = asyncio.to_thread(psutil.disk_usage, '/')
            net_io_counters_task = asyncio.to_thread(psutil.net_io_counters)
            
            # Tunggu semua task selesai
            results = await asyncio.gather(
                uptime_task, os_info_task, kernel_info_task, 
                cpu_percent_task, virtual_memory_task, disk_usage_task, net_io_counters_task
            )
            
            uptime_stdout, _, _ = results[0]
            os_info_stdout, _, _ = results[1]
            kernel_info_stdout, _, _ = results[2]
            cpu_percent = results[3]
            memory = results[4]
            disk = results[5]
            network = results[6]
            
            hostname = os.uname().nodename
            
            info = f"""
🖥️ *System Information*

📡 **Hostname:** `{hostname}`
🐧 **OS:** `{os_info_stdout.strip()}`
🔧 **Kernel:** `{kernel_info_stdout.strip()}`
⏰ **Uptime:** `{uptime_stdout.strip()}`

💻 **CPU Usage:** `{cpu_percent}%`
🧠 **Memory:** `{memory.percent:.1f}%` ({memory.available // (1024**3):.1f}GB available)
📊 **Total RAM:** `{memory.total // (1024**3):.1f} GB`

💾 **Disk Usage:** `{disk.percent:.1f}%`
📁 **Free Space:** `{disk.free // (1024**3):.1f} GB`
💿 **Total Disk:** `{disk.total // (1024**3):.1f} GB`

🌐 **Network:**
📤 **Sent:** `{network.bytes_sent // (1024**2)} MB`
📥 **Received:** `{network.bytes_recv // (1024**2)} MB`

🔄 **Load Average:** `{os.getloadavg()[0]:.2f}, {os.getloadavg()[1]:.2f}, {os.getloadavg()[2]:.2f}`
"""
            
            await query.edit_message_text(info, parse_mode='Markdown', reply_markup=self._get_back_button())
            
        except Exception as e:
            logger.error(f"Error getting system info: {e}")
            await query.edit_message_text(f"❌ Error getting system info: {str(e)}", reply_markup=self._get_back_button())

    async def reboot_server(self, query):
        """Reboot server dengan konfirmasi"""
        keyboard = [
            [InlineKeyboardButton("✅ Ya, Reboot", callback_data='confirm_reboot')],
            [InlineKeyboardButton("❌ Batal", callback_data='cancel')]
        ]
        reply_markup = InlineKeyboardMarkup(keyboard)
        
        await query.edit_message_text(
            "⚠️ *Konfirmasi Reboot*\n\n"
            "Apakah Anda yakin ingin mereboot server?\n"
            "Server akan offline sementara.\n\n"
            "⏱️ Estimasi downtime: 1-3 menit",
            parse_mode='Markdown',
            reply_markup=reply_markup
        )

    async def change_password_prompt(self, query):
        """Prompt untuk mengganti password root"""
        user_id = query.from_user.id
        self.waiting_for_password.add(user_id)
        
        await query.edit_message_text(
            "🔐 *Change Root Password*\n\n"
            "Kirim password baru untuk user root.\n\n"
            "⚠️ **Catatan Keamanan:**\n"
            "• Password akan dihapus setelah diproses\n"
            "• Gunakan password yang kuat\n"
            "• Pesan akan dihapus otomatis\n\n"
            "Ketik `/cancel` untuk membatalkan.",
            parse_mode='Markdown',
            reply_markup=self._get_back_button()
        )

    async def custom_command_prompt(self, query):
        """Prompt untuk custom command"""
        user_id = query.from_user.id
        self.waiting_for_command.add(user_id)
        
        await query.edit_message_text(
            "⚡ *Custom Command*\n\n"
            "Kirim command yang ingin dijalankan.\n\n"
            "⚠️ **Peringatan:**\n"
            "• Command berbahaya akan ditolak\n"
            "• Timeout: 30 detik\n"
            "• Gunakan dengan hati-hati\n\n"
            "Ketik `/cancel` untuk membatalkan.",
            parse_mode='Markdown',
            reply_markup=self._get_back_button()
        )

    async def message_handler(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Handler untuk pesan text"""
        user_id = update.effective_user.id
        chat_id = update.effective_chat.id
        
        if not self.is_admin(chat_id):
            return
        
        message_text = update.message.text
        
        # Handle cancel command
        if message_text == '/cancel':
            self.waiting_for_password.discard(user_id)
            self.waiting_for_command.discard(user_id)
            await update.message.reply_text("❌ Operasi dibatalkan.", reply_markup=self._get_back_button())
            try:
                await update.message.delete()
            except:
                pass # Ignore if message already deleted
            return
        
        # Handle password input
        if user_id in self.waiting_for_password:
            await self.handle_password_change(update, message_text)
            return
        
        # Handle custom command input
        if user_id in self.waiting_for_command:
            await self.handle_custom_command(update, message_text)
            return

    async def handle_password_change(self, update, new_password):
        """Handle perubahan password root"""
        user_id = update.effective_user.id
        
        try:
            # Hapus pesan password segera
            await update.message.delete()
            
            # Validasi password
            if len(new_password) < 6:
                await update.message.reply_text("❌ Password minimal 6 karakter!", reply_markup=self._get_back_button())
                return
            
            # Escape password untuk shell
            escaped_password = shlex.quote(new_password)
            command = f"echo 'root:{escaped_password}' | chpasswd"
            
            stdout, stderr, retcode = await self.run_command(command)
            
            if retcode != 0:
                error_message = stderr if stderr else stdout
                await update.message.reply_text(f"❌ Gagal mengganti password:\n```\n{error_message}\n```", parse_mode='Markdown', reply_markup=self._get_back_button())
            else:
                await update.message.reply_text("✅ Password root berhasil diubah!", reply_markup=self._get_back_button())
                logger.info(f"Root password changed by user {user_id}")
            
        except Exception as e:
            logger.error(f"Error changing password: {e}")
            await update.message.reply_text(f"❌ Error: {str(e)}", reply_markup=self._get_back_button())
        finally:
            self.waiting_for_password.discard(user_id)

    async def handle_custom_command(self, update, command):
        """Handle custom command"""
        user_id = update.effective_user.id
        
        try:
            await update.message.delete()
            
            # Send "processing" message
            processing_msg = await update.message.reply_text(f"⚡ Menjalankan command: `{command[:50]}...`", parse_mode='Markdown')
            
            stdout, stderr, retcode = await self.run_command(command)
            
            output = f"Exit Code: {retcode}\n"
            if stdout:
                output += f"\n--- STDOUT ---\n{stdout}\n"
            if stderr:
                output += f"\n--- STDERR ---\n{stderr}\n"

            if len(output) > 4000:
                output = output[:4000] + "\n\n... (output dipotong)"
            
            await processing_msg.edit_text(f"⚡ *Command Output:*\n\n```\n{output}\n```", parse_mode='Markdown', reply_markup=self._get_back_button())
            logger.info(f"Custom command executed by user {user_id}: {command}")
            
        except Exception as e:
            logger.error(f"Error executing custom command: {e}")
            await update.message.reply_text(f"❌ Error: {str(e)}", reply_markup=self._get_back_button())
        finally:
            self.waiting_for_command.discard(user_id)

    async def speedtest(self, query):
        """Menjalankan speedtest"""
        try:
            await query.edit_message_text("🌐 Menjalankan speedtest... (ini mungkin memakan waktu 30-60 detik)")
            
            # Check if speedtest-cli is installed
            _, _, retcode = await self.run_command("which speedtest-cli")
            if retcode != 0:
                await query.edit_message_text("📦 speedtest-cli tidak ditemukan, menginstall...")
                _, stderr, install_retcode = await self.run_command("pip3 install speedtest-cli --break-system-packages")
                if install_retcode != 0:
                    await query.edit_message_text(f"❌ Gagal menginstall speedtest-cli:\n```\n{stderr}\n```", parse_mode='Markdown', reply_markup=self._get_back_button())
                    return

            stdout, stderr, retcode = await self.run_command("speedtest-cli --simple", timeout=120)
            
            if retcode == 0 and stdout:
                await query.edit_message_text(f"🌐 *Speedtest Results*\n\n```\n{stdout}\n```", parse_mode='Markdown', reply_markup=self._get_back_button())
            else:
                error_message = stderr if stderr else "Output kosong."
                await query.edit_message_text(f"❌ Gagal menjalankan speedtest.\n\n`{error_message}`", reply_markup=self._get_back_button())
        except Exception as e:
            logger.error(f"Error running speedtest: {e}")
            await query.edit_message_text(f"❌ Error speedtest: {str(e)}", reply_markup=self._get_back_button())

    async def disk_usage(self, query):
        """Menampilkan penggunaan disk"""
        try:
            stdout, stderr, retcode = await self.run_command("df -h")
            if retcode == 0:
                await query.edit_message_text(f"💾 *Disk Usage*\n\n```\n{stdout}\n```", parse_mode='Markdown', reply_markup=self._get_back_button())
            else:
                await query.edit_message_text(f"❌ Gagal mengambil info disk:\n```\n{stderr}\n```", parse_mode='Markdown', reply_markup=self._get_back_button())
        except Exception as e:
            await query.edit_message_text(f"❌ Error: {str(e)}", reply_markup=self._get_back_button())

    async def resource_monitor(self, query):
        """Monitor resource real-time"""
        try:
            await query.edit_message_text("📈 Mengumpulkan data resource...")
            
            # Jalankan psutil calls di thread terpisah
            cpu_task = asyncio.to_thread(psutil.cpu_percent, interval=1)
            mem_task = asyncio.to_thread(psutil.virtual_memory)
            disk_task = asyncio.to_thread(psutil.disk_usage, '/')
            
            cpu, memory, disk = await asyncio.gather(cpu_task, mem_task, disk_task)
            load_avg = os.getloadavg()
            
            # Get top processes (ini juga blocking, tapi cepat)
            processes = []
            def get_procs():
                for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                    try:
                        proc_info = proc.info
                        if proc_info['cpu_percent'] and proc_info['cpu_percent'] > 0:
                            processes.append(proc_info)
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        continue
                return sorted(processes, key=lambda x: x['cpu_percent'] or 0, reverse=True)[:5]
            
            top_processes = await asyncio.to_thread(get_procs)

            monitor_text = f"""
📈 *Resource Monitor*

**💻 CPU Usage:** `{cpu:.1f}%`
**⚖️ Load Average:** `{load_avg[0]:.2f}, {load_avg[1]:.2f}, {load_avg[2]:.2f}`

**🧠 Memory:** `{memory.percent:.1f}%`
**📊 Used:** `{memory.used // (1024**3):.1f} GB`
**📈 Available:** `{memory.available // (1024**3):.1f} GB`

**💾 Disk:** `{disk.percent:.1f}%`
**📁 Free:** `{disk.free // (1024**3):.1f} GB`

**🔥 Top CPU Processes:**
"""
            
            for proc in top_processes:
                if proc['cpu_percent']:
                    monitor_text += f"• `{proc['name'][:15]}` ({proc['pid']}): {proc['cpu_percent']:.1f}%\n"
            
            await query.edit_message_text(monitor_text, parse_mode='Markdown', reply_markup=self._get_back_button())
            
        except Exception as e:
            logger.error(f"Error monitoring resources: {e}")
            await query.edit_message_text(f"❌ Error monitoring resources: {str(e)}", reply_markup=self._get_back_button())

    async def services_status(self, query):
        """Cek status layanan penting dengan cara yang lebih andal"""
        try:
            await query.edit_message_text("🔧 Mengecek status layanan...")
            services = ['ssh', 'sshd', 'nginx', 'apache2', 'mysql', 'mariadb', 'postgresql', 'docker', 'ufw']
            status_text = "🔧 *Services Status*\n\n"
            
            checked_services = set()
            
            for service in services:
                if service in checked_services:
                    continue
                
                # Gunakan `systemctl status` untuk exit code yang andal
                _, _, retcode = await self.run_command(f"systemctl status {service} > /dev/null 2>&1")
                
                if retcode == 4: # Unit not found
                    status_text += f"❓ `{service}`: Not installed\n"
                    continue

                # Cek is-active dan is-enabled secara paralel
                active_task = self.run_command(f"systemctl is-active {service}")
                enabled_task = self.run_command(f"systemctl is-enabled {service}")
                
                active_res, enabled_res = await asyncio.gather(active_task, enabled_task)
                
                status = active_res[0].strip()
                enabled_status = "enabled" if enabled_res[2] == 0 else "disabled"

                if status == "active":
                    status_text += f"✅ `{service}`: Running ({enabled_status})\n"
                elif status == "failed":
                    status_text += f"❌ `{service}`: Failed ({enabled_status})\n"
                else: # inactive, deactivating, etc.
                    status_text += f"⏸️ `{service}`: Stopped ({enabled_status})\n"

                checked_services.add(service)

            await query.edit_message_text(status_text, parse_mode='Markdown', reply_markup=self._get_back_button())
        except Exception as e:
            logger.error(f"Error checking services status: {e}")
            await query.edit_message_text(f"❌ Error: {str(e)}", reply_markup=self._get_back_button())

    async def running_processes(self, query):
        """Menampilkan proses yang berjalan"""
        try:
            stdout, stderr, retcode = await self.run_command("ps aux --sort=-%cpu | head -20")
            
            if retcode == 0:
                if len(stdout) > 4000:
                    stdout = stdout[:4000] + "\n... (output dipotong)"
                await query.edit_message_text(f"📋 *Running Processes*\n\n```\n{stdout}\n```", parse_mode='Markdown', reply_markup=self._get_back_button())
            else:
                await query.edit_message_text(f"❌ Gagal mengambil daftar proses:\n```\n{stderr}\n```", parse_mode='Markdown', reply_markup=self._get_back_button())
        except Exception as e:
            await query.edit_message_text(f"❌ Error: {str(e)}", reply_markup=self._get_back_button())

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        """Command /help"""
        if not self.is_admin(update.effective_chat.id):
            await update.message.reply_text("❌ Akses ditolak.")
            return
            
        help_text = """
🖥️ *VPS Admin Bot Commands*

**📋 Available Commands:**
/start - Panel utama
/help - Bantuan ini
/cancel - Batalkan operasi yang sedang berjalan

**⚡ Features:**
• 📊 System monitoring
• 🔐 Password management
• 🌐 Network testing
• ⚡ Custom commands
• 🔧 Service management

**⚠️ Security Notes:**
• Bot hanya dapat diakses oleh admin terdaftar
• Password dihapus otomatis setelah diproses
• Command berbahaya akan ditolak
• Semua aktivitas dicatat dalam log

**🔧 Management:**
• Restart bot: `systemctl restart vps-admin-bot`
• View logs: `journalctl -u vps-admin-bot -f`
• Config: `/opt/vps-admin-bot/bot_config.json`
"""
        await update.message.reply_text(help_text, parse_mode='Markdown')

def main():
    """Fungsi utama"""
    if not BOT_TOKEN:
        logger.error("Bot token tidak ditemukan! Periksa file konfigurasi.")
        print("❌ Bot token tidak ditemukan!")
        print("Edit file: /opt/vps-admin-bot/bot_config.json")
        return
    
    if not ADMIN_CHAT_IDS:
        logger.error("Admin chat IDs tidak ditemukan! Periksa file konfigurasi.")
        print("❌ Admin chat IDs tidak ditemukan!")
        print("Edit file: /opt/vps-admin-bot/bot_config.json")
        return
        
    bot = VPSAdminBot()
    application = Application.builder().token(BOT_TOKEN).build()
    
    # Add handlers
    application.add_handler(CommandHandler("start", bot.start))
    application.add_handler(CommandHandler("help", bot.help_command))
    application.add_handler(CallbackQueryHandler(bot.button_handler))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, bot.message_handler))
    
    logger.info("VPS Admin Bot started...")
    print("✅ VPS Admin Bot started successfully!")
    print(f"📋 Admin Chat IDs: {ADMIN_CHAT_IDS}")
    print("📊 Bot is running and ready to accept commands...")
    
    try:
        application.run_polling()
    except Exception as e:
        logger.error(f"Bot crashed: {e}")
        print(f"❌ Bot crashed: {e}")

if __name__ == '__main__':
    main()
EOF

    chmod +x $BOT_DIR/$PYTHON_FILE
    print_success "Bot file created successfully"
}

# Fungsi untuk membuat service systemd
create_systemd_service() {
    print_info "Creating systemd service..."
    
    cat > /etc/systemd/system/$SERVICE_NAME.service << EOF
[Unit]
Description=VPS Admin Telegram Bot
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=$BOT_DIR
Environment=PATH=$BOT_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
ExecStart=$BOT_DIR/venv/bin/python $BOT_DIR/$PYTHON_FILE
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
KillMode=mixed
KillSignal=SIGINT
TimeoutStopSec=30

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable $SERVICE_NAME
    
    print_success "Systemd service created and enabled"
}

# Fungsi untuk konfigurasi bot
configure_bot() {
    print_info "Configuring bot..."
    
    echo
    echo "==================================="
    echo "    KONFIGURASI BOT TELEGRAM"
    echo "==================================="
    echo
    
    # Input bot token
    while true; do
        echo -n "Masukkan Bot Token dari @BotFather: "
        read BOT_TOKEN
        
        if [[ -z "$BOT_TOKEN" ]]; then
            print_error "Bot token tidak boleh kosong!"
            continue
        fi
        
        # Validasi format token
        if [[ ! $BOT_TOKEN =~ ^[0-9]+:[a-zA-Z0-9_-]+$ ]]; then
            print_error "Format bot token tidak valid!"
            continue
        fi
        
        break
    done
    
    # Input admin chat IDs
    while true; do
        echo -n "Masukkan Chat ID admin (pisahkan dengan koma jika lebih dari satu): "
        read CHAT_IDS
        
        if [[ -z "$CHAT_IDS" ]]; then
            print_error "Chat ID tidak boleh kosong!"
            continue
        fi
        
        break
    done
    
    # Convert chat IDs ke array format JSON
    IFS=',' read -ra CHAT_ID_ARRAY <<< "$CHAT_IDS"
    CHAT_ID_JSON="["
    for i in "${!CHAT_ID_ARRAY[@]}"; do
        if [[ $i -gt 0 ]]; then
            CHAT_ID_JSON+=","
        fi
        # Remove spaces and validate numeric
        CLEAN_ID="${CHAT_ID_ARRAY[$i]// /}"
        if [[ $CLEAN_ID =~ ^-?[0-9]+$ ]]; then
            CHAT_ID_JSON+="$CLEAN_ID"
        else
            print_error "Invalid chat ID: $CLEAN_ID"
            exit 1
        fi
    done
    CHAT_ID_JSON+="]"
    
    # Buat file konfigurasi
    cat > $BOT_DIR/$CONFIG_FILE << EOF
{
    "bot_token": "$BOT_TOKEN",
    "admin_chat_ids": $CHAT_ID_JSON,
    "created_at": "$(date -Iseconds)",
    "version": "2.0"
}
EOF
    
    chmod 600 $BOT_DIR/$CONFIG_FILE
    chown root:root $BOT_DIR/$CONFIG_FILE
    
    print_success "Bot configuration saved"
    echo "Config file: $BOT_DIR/$CONFIG_FILE"
}

# Fungsi untuk test bot configuration
test_bot_config() {
    print_info "Testing bot configuration..."
    
    cd $BOT_DIR
    source venv/bin/activate
    
    # Test python script syntax
    python3 -m py_compile $PYTHON_FILE
    if [[ $? -eq 0 ]]; then
        print_success "Python script syntax OK"
    else
        print_error "Python script has syntax errors!"
        exit 1
    fi
    
    # Test bot token by making a simple API call
    python3 -c "
import json
import requests
import sys

try:
    with open('$CONFIG_FILE', 'r') as f:
        config = json.load(f)
    
    token = config['bot_token']
    response = requests.get(f'https://api.telegram.org/bot{token}/getMe', timeout=10)
    
    if response.status_code == 200:
        bot_info = response.json()
        if bot_info['ok']:
            print(f'✅ Bot token valid: @{bot_info[\"result\"][\"username\"]}')
            sys.exit(0)
        else:
            print('❌ Bot token invalid')
            sys.exit(1)
    else:
        print('❌ Cannot connect to Telegram API')
        sys.exit(1)
        
except Exception as e:
    print(f'❌ Error testing bot token: {e}')
    sys.exit(1)
"
    
    if [[ $? -eq 0 ]]; then
        print_success "Bot token validation passed"
    else
        print_error "Bot token validation failed!"
        print_warning "Bot mungkin tetap berjalan, tapi pastikan token benar"
    fi
}

# Fungsi untuk start bot
start_bot() {
    print_info "Starting VPS Admin Bot..."
    
    systemctl start $SERVICE_NAME
    sleep 5
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        print_success "Bot started successfully!"
        echo
        echo "Bot Status: $(systemctl is-active $SERVICE_NAME)"
        echo "Bot Logs: journalctl -u $SERVICE_NAME -f"
        echo "Config File: $BOT_DIR/$CONFIG_FILE"
        echo "Log File: $LOG_FILE"
        echo
        print_info "Checking bot logs..."
        sleep 2
        journalctl -u $SERVICE_NAME -n 10 --no-pager
    else
        print_error "Failed to start bot!"
        echo "Check logs: journalctl -u $SERVICE_NAME -n 20"
        echo "Recent logs:"
        journalctl -u $SERVICE_NAME -n 20 --no-pager
        exit 1
    fi
}

# Fungsi untuk install bot
install_bot() {
    print_info "Starting VPS Admin Bot installation..."
    
    check_root
    install_dependencies
    setup_environment
    create_bot_file
    create_systemd_service
    configure_bot
    test_bot_config
    start_bot
    
    echo
    echo "==================================="
    echo "    INSTALASI SELESAI!"
    echo "==================================="
    echo
    echo "✅ VPS Admin Bot berhasil diinstall dan dijalankan!"
    echo
    echo "📋 Informasi:"
    echo "   • Service: $SERVICE_NAME"
    echo "   • Directory: $BOT_DIR"
    echo "   • Log File: $LOG_FILE"
    echo "   • Config: $BOT_DIR/$CONFIG_FILE"
    echo
    echo "🔧 Management Commands:"
    echo "   • Start bot: systemctl start $SERVICE_NAME"
    echo "   • Stop bot: systemctl stop $SERVICE_NAME"
    echo "   • Restart bot: systemctl restart $SERVICE_NAME"
    echo "   • Status: systemctl status $SERVICE_NAME"
    echo "   • Logs: journalctl -u $SERVICE_NAME -f"
    echo
    echo "📱 Cara menggunakan:"
    echo "   1. Buka Telegram dan cari bot Anda"
    echo "   2. Kirim perintah /start"
    echo "   3. Gunakan tombol inline untuk mengakses fitur"
    echo
    echo "🔐 Fitur yang tersedia:"
    echo "   • System Information & Monitoring"
    echo "   • Change Root Password (FIXED)"
    echo "   • Speedtest Network"
    echo "   • Custom Commands"
    echo "   • Service Management"
    echo "   • Resource Monitoring"
    echo
    echo "🗑️  Untuk uninstall: bash $0 uninstall"
    echo
}

# Fungsi untuk uninstall bot
uninstall_bot() {
    print_warning "Starting VPS Admin Bot uninstallation..."
    
    check_root
    
    # Konfirmasi
    echo -n "Apakah Anda yakin ingin menghapus VPS Admin Bot? (y/N): "
    read -r confirm
    
    if [[ ! $confirm =~ ^[Yy]$ ]]; then
        print_info "Uninstallation cancelled."
        exit 0
    fi
    
    print_info "Stopping and removing service..."
    
    # Stop dan disable service
    if systemctl is-active --quiet $SERVICE_NAME; then
        systemctl stop $SERVICE_NAME
        print_success "Service stopped"
    fi
    
    if systemctl is-enabled --quiet $SERVICE_NAME 2>/dev/null; then
        systemctl disable $SERVICE_NAME
        print_success "Service disabled"
    fi
    
    # Hapus service file
    if [[ -f "/etc/systemd/system/$SERVICE_NAME.service" ]]; then
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload
        print_success "Service file removed"
    fi
    
    # Hapus directory bot
    if [[ -d "$BOT_DIR" ]]; then
        rm -rf "$BOT_DIR"
        print_success "Bot directory removed"
    fi
    
    # Hapus log file
    if [[ -f "$LOG_FILE" ]]; then
        rm -f "$LOG_FILE"
        print_success "Log file removed"
    fi
    
    print_success "VPS Admin Bot successfully uninstalled!"
    echo
    echo "Semua file dan service telah dihapus."
    echo "Terima kasih telah menggunakan VPS Admin Bot!"
}

# Fungsi untuk show status
show_status() {
    echo "==================================="
    echo "    VPS ADMIN BOT STATUS"
    echo "==================================="
    echo
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        print_success "Bot Status: RUNNING"
        echo "Uptime: $(systemctl show $SERVICE_NAME --property=ActiveEnterTimestamp --value)"
    else
        print_error "Bot Status: STOPPED"
    fi
    
    if [[ -f "$BOT_DIR/$CONFIG_FILE" ]]; then
        print_success "Config File: EXISTS"
        echo "Config: $BOT_DIR/$CONFIG_FILE"
        
        # Show config info
        if command -v jq &> /dev/null; then
            echo "Admin IDs: $(jq -r '.admin_chat_ids | join(", ")' $BOT_DIR/$CONFIG_FILE 2>/dev/null || echo "Cannot parse")"
        fi
    else
        print_error "Config File: MISSING"
    fi
    
    if [[ -d "$BOT_DIR" ]]; then
        print_success "Bot Directory: EXISTS"
        echo "Directory: $BOT_DIR"
        echo "Python File: $BOT_DIR/$PYTHON_FILE"
    else
        print_error "Bot Directory: MISSING"
    fi
    
    if [[ -f "$LOG_FILE" ]]; then
        print_success "Log File: EXISTS"
        echo "Log File: $LOG_FILE"
        echo "Log Size: $(du -h $LOG_FILE | cut -f1)"
    else
        print_warning "Log File: MISSING"
    fi
    
    echo
    echo "==================================="
    echo "    SYSTEMD SERVICE STATUS"
    echo "==================================="
    systemctl status $SERVICE_NAME --no-pager
    
    echo
    echo "==================================="
    echo "    RECENT LOGS (Last 10 lines)"
    echo "==================================="
    journalctl -u $SERVICE_NAME -n 10 --no-pager
}

# Fungsi untuk update bot
update_bot() {
    print_info "Updating VPS Admin Bot..."
    
    check_root
    
    if [[ ! -d "$BOT_DIR" ]]; then
        print_error "Bot not installed! Run: $0 install"
        exit 1
    fi
    
    # Backup current config
    if [[ -f "$BOT_DIR/$CONFIG_FILE" ]]; then
        cp "$BOT_DIR/$CONFIG_FILE" "$BOT_DIR/$CONFIG_FILE.backup"
        print_success "Config backed up"
    fi
    
    # Stop bot
    if systemctl is-active --quiet $SERVICE_NAME; then
        systemctl stop $SERVICE_NAME
        print_success "Bot stopped"
    fi
    
    # Update dependencies
    cd $BOT_DIR
    source venv/bin/activate
    pip install --upgrade python-telegram-bot psutil requests
    
    # Recreate bot file
    create_bot_file
    
    # Restart bot
    systemctl start $SERVICE_NAME
    sleep 3
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        print_success "Bot updated and restarted successfully!"
    else
        print_error "Failed to restart bot after update!"
        echo "Check logs: journalctl -u $SERVICE_NAME -n 20"
    fi
}

# Fungsi untuk backup config
backup_config() {
    print_info "Creating backup..."
    
    if [[ ! -f "$BOT_DIR/$CONFIG_FILE" ]]; then
        print_error "Config file not found!"
        exit 1
    fi
    
    BACKUP_DIR="/opt/vps-admin-bot-backup"
    mkdir -p $BACKUP_DIR
    
    BACKUP_FILE="$BACKUP_DIR/bot_config_$(date +%Y%m%d_%H%M%S).json"
    cp "$BOT_DIR/$CONFIG_FILE" "$BACKUP_FILE"
    
    print_success "Config backed up to: $BACKUP_FILE"
}

# Fungsi untuk restore config
restore_config() {
    print_info "Available backups:"
    
    BACKUP_DIR="/opt/vps-admin-bot-backup"
    if [[ ! -d "$BACKUP_DIR" ]]; then
        print_error "No backups found!"
        exit 1
    fi
    
    ls -la $BACKUP_DIR/
    
    echo -n "Enter backup filename to restore: "
    read BACKUP_FILE
    
    if [[ -f "$BACKUP_DIR/$BACKUP_FILE" ]]; then
        cp "$BACKUP_DIR/$BACKUP_FILE" "$BOT_DIR/$CONFIG_FILE"
        systemctl restart $SERVICE_NAME
        print_success "Config restored and bot restarted!"
    else
        print_error "Backup file not found!"
    fi
}

# Main menu
case "${1:-install}" in
    "install")
        install_bot
        ;;
    "uninstall")
        uninstall_bot
        ;;
    "status")
        show_status
        ;;
    "restart")
        check_root
        print_info "Restarting VPS Admin Bot..."
        systemctl restart $SERVICE_NAME
        sleep 3
        if systemctl is-active --quiet $SERVICE_NAME; then
            print_success "Bot restarted successfully!"
        else
            print_error "Failed to restart bot!"
            echo "Check logs: journalctl -u $SERVICE_NAME -n 10"
        fi
        ;;
    "logs")
        print_info "Showing bot logs (Ctrl+C to exit)..."
        journalctl -u $SERVICE_NAME -f
        ;;
    "update")
        update_bot
        ;;
    "backup")
        backup_config
        ;;
    "restore")
        restore_config
        ;;
    "test")
        check_root
        test_bot_config
        ;;
    *)
        echo "VPS Admin Bot Installer"
        echo "Usage: $0 {install|uninstall|status|restart|logs|update|backup|restore|test}"
        echo
        echo "Commands:"
        echo "  install   - Install and setup the bot"
        echo "  uninstall - Remove the bot completely"
        echo "  status    - Show bot status and detailed info"
        echo "  restart   - Restart the bot service"
        echo "  logs      - Show bot logs (real-time)"
        echo "  update    - Update bot to latest version"
        echo "  backup    - Backup bot configuration"
        echo "  restore   - Restore bot configuration"
        echo "  test      - Test bot configuration"
        echo
        echo "Examples:"
        echo "  $0 install          # Install new bot"
        echo "  $0 status           # Check bot status"
        echo "  $0 logs             # View live logs"
        echo "  $0 restart          # Restart bot service"
        echo
        exit 1
        ;;
esac
