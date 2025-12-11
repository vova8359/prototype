# -*- coding: utf-8 -*-
"""Скрипт для тестування авторизації в OLX без проксі з збереженням токена та моніторингом повідомлень"""
import asyncio
import sys
import json
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, Set, List, Optional

# Додаємо шлях до папки авторизації
sys.path.insert(0, str(Path(__file__).parent / "авторизація"))

from olx_auth import challenge, exchange, initiate_auth, get_token, create_connector
import aiohttp


# Шлях до файлу з токеном
TOKEN_FILE = Path(__file__).parent / "bearer_token.json"

# Базовий URL для Chat API
CHAT_BASE_URL = "https://api.chat.olx.ua/api"


def save_token(tokens: dict, username: str) -> None:
    """
    Зберігає токен в файл з часом дії
    
    Args:
        tokens: Словник з токенами
        username: Логін користувача
    """
    try:
        # Обчислюємо expires_at
        expires_at = None
        if "expires_in" in tokens:
            expires_in = int(tokens.get("expires_in", 900))
            expires_at = (datetime.now() + timedelta(seconds=expires_in)).isoformat()
        
        data = {
            "username": username,
            "tokens": tokens,
            "saved_at": datetime.now().isoformat(),
            "expires_at": expires_at
        }
        
        with open(TOKEN_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        
        print(f"✅ Токен збережено в {TOKEN_FILE}")
        
    except Exception as e:
        print(f"⚠️ Помилка збереження токена: {e}")


def load_token() -> dict:
    """
    Завантажує токен з файлу
    
    Returns:
        Словник з токенами або None якщо токен відсутній або невалідний
    """
    try:
        if not TOKEN_FILE.exists():
            return None
        
        with open(TOKEN_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Перевіряємо чи не вийшов час дії
        expires_at_str = data.get("expires_at")
        if expires_at_str:
            expires_at = datetime.fromisoformat(expires_at_str)
            if datetime.now() >= expires_at:
                print("⚠️ Токен вийшов строк дії")
                return None
        
        tokens = data.get("tokens", {})
        if "access_token" in tokens:
            return tokens
        
        return None
        
    except Exception as e:
        print(f"⚠️ Помилка завантаження токена: {e}")
        return None


async def auth_without_proxy(username: str, password: str) -> dict:
    """
    Авторизація без проксі
    
    Args:
        username: Логін користувача
        password: Пароль користувача
        
    Returns:
        Словник з токенами
    """
    connector = create_connector()
    async with aiohttp.ClientSession(connector=connector) as session:
        # Крок 1: Challenge
        challenge_result = await challenge(username, proxy=None, session=session)
        context = challenge_result.get("context")
        if not context:
            raise Exception("Не отримано context з challenge запиту")
        
        # Крок 2: Exchange
        exchange_result = await exchange(context, proxy=None, session=session)
        friction_token = exchange_result.get("token")
        if not friction_token:
            raise Exception("Не отримано friction-token з exchange запиту")
        
        # Крок 3: Initiate-auth
        auth_code, code_verifier = await initiate_auth(username, password, friction_token, proxy=None, session=session)
        
        # Крок 4: Get token
        tokens = await get_token(auth_code, code_verifier, proxy=None, session=session)
        
        if "access_token" not in tokens:
            raise Exception("Не отримано access_token")
        
        return tokens


async def get_conversations(access_token: str, session: aiohttp.ClientSession, 
                           unread: Optional[int] = None, offset: int = 0, limit: int = 40) -> Dict:
    """
    Отримує список чатів
    
    Args:
        access_token: Bearer токен
        session: aiohttp сесія
        unread: None - всі, 0 - прочитані, 1 - непрочитані
        offset: Зміщення для пагінації
        limit: Кількість елементів
        
    Returns:
        Словник зі списком чатів
    """
    url = f"{CHAT_BASE_URL}/conversations"
    params = {
        "my_ads": "0",
        "archived": "0",
        "offset": str(offset),
        "limit": str(limit)
    }
    
    if unread is not None:
        params["unread"] = str(unread)
    
    headers = {
        "accept": "*/*",
        "accept-language": "uk-UA, uk",
        "authorization": f"Bearer {access_token}"
    }
    
    async with session.get(url, headers=headers, params=params) as response:
        if response.status == 200:
            return await response.json()
        else:
            text = await response.text()
            raise Exception(f"HTTP {response.status}: {text[:200]}")


async def get_counters(access_token: str, session: aiohttp.ClientSession) -> Dict:
    """
    Отримує статистику повідомлень (counters)
    
    Args:
        access_token: Bearer токен
        session: aiohttp сесія
        
    Returns:
        Словник зі статистикою: {"data": {"active": {"read": X, "unread": Y}, ...}}
    """
    url = f"{CHAT_BASE_URL}/conversations/counters"
    headers = {
        "accept": "*/*",
        "accept-language": "uk-UA, uk",
        "authorization": f"Bearer {access_token}"
    }
    
    async with session.get(url, headers=headers) as response:
        if response.status == 200:
            return await response.json()
        else:
            text = await response.text()
            raise Exception(f"HTTP {response.status}: {text[:200]}")


async def get_conversation(access_token: str, session: aiohttp.ClientSession, 
                          conversation_id: str) -> Dict:
    """
    Отримує конкретний чат з повідомленнями
    
    Args:
        access_token: Bearer токен
        session: aiohttp сесія
        conversation_id: ID чату
        
    Returns:
        Словник з інформацією про чат та повідомлення
    """
    url = f"{CHAT_BASE_URL}/conversations/{conversation_id}"
    headers = {
        "accept": "*/*",
        "accept-language": "uk-UA, uk",
        "authorization": f"Bearer {access_token}",
        "x-api-version": "2"
    }
    
    async with session.get(url, headers=headers) as response:
        if response.status == 200:
            return await response.json()
        else:
            text = await response.text()
            raise Exception(f"HTTP {response.status}: {text[:200]}")


class MessageMonitor:
    """Моніторинг нових повідомлень"""
    
    def __init__(self, access_token: str, thread_id: Optional[int] = None, short_output: bool = False):
        self.access_token = access_token
        self.thread_id = thread_id
        self.short_output = short_output
        self.last_message_ids: Dict[str, Set[str]] = {}
        self.initialized = False
        self.running = False
        self.check_interval = 0.3  # 0.3 секунди для максимальної швидкості
    
    async def initialize(self, session: aiohttp.ClientSession):
        """Ініціалізація - завантажує поточні повідомлення (оптимізовано)"""
        thread_prefix = f"[Потік {self.thread_id}] " if self.thread_id is not None else "[Моніторинг] "
        if not self.short_output:
            print(f"\n{thread_prefix}Ініціалізація...")
        
        try:
            # ОПТИМІЗАЦІЯ: Спочатку перевіряємо counters
            counters_data = await get_counters(self.access_token, session)
            counters = counters_data.get("data", {})
            active_counters = counters.get("active", {})
            unread_count = active_counters.get("unread", 0)
            read_count = active_counters.get("read", 0)
            
            # Отримуємо непрочитані чати
            unread_data = await get_conversations(self.access_token, session, unread=1)
            unread_conversations = unread_data.get("data", [])
            
            # ОПТИМІЗАЦІЯ: Завантажуємо прочитані чати тільки якщо є прочитані
            # (для ініціалізації потрібно знати всі чати, але якщо їх багато - можна пропустити)
            all_conversations = list(unread_conversations)
            if read_count > 0 and read_count <= 100:  # Завантажуємо прочитані тільки якщо їх небагато
                read_data = await get_conversations(self.access_token, session, unread=0)
                read_conversations = read_data.get("data", [])
                
                # Об'єднуємо, уникаючи дублікатів
                all_conversation_ids = {conv.get("id") for conv in unread_conversations}
                for conv in read_conversations:
                    conv_id = conv.get("id")
                    if conv_id and conv_id not in all_conversation_ids:
                        all_conversations.append(conv)
            
            if not self.short_output:
                print(f"{thread_prefix}Знайдено {len(all_conversations)} чатів (непрочитаних: {len(unread_conversations)})")
            
            # ОПТИМІЗОВАНО: Використовуємо messages зі списку чатів (не робимо окремі запити!)
            for conv in all_conversations:
                conv_id = conv.get("id", "")
                if not conv_id:
                    continue
                
                # Використовуємо messages зі списку чатів
                messages_list = conv.get("messages", [])
                if messages_list:
                    # При ініціалізації зберігаємо ВСІ ID (щоб не виводити старі повідомлення як нові)
                    all_ids = {msg.get("id", "") for msg in messages_list if msg.get("id")}
                    self.last_message_ids[conv_id] = all_ids
            
            self.initialized = True
            if not self.short_output:
                print(f"{thread_prefix}Ініціалізовано {len(self.last_message_ids)} чатів")
            
        except Exception as e:
            print(f"{thread_prefix}Помилка ініціалізації: {e}")
            import traceback
            traceback.print_exc()
    
    async def check_new_messages(self, session: aiohttp.ClientSession) -> List[Dict]:
        """Перевіряє нові повідомлення - МАКСИМАЛЬНО ОПТИМІЗОВАНО: використовує дані зі списку чатів"""
        new_messages = []
        thread_prefix = f"[Потік {self.thread_id}] " if self.thread_id is not None else "[Моніторинг] "
        
        try:
            # КРИТИЧНА ОПТИМІЗАЦІЯ 1: Спочатку перевіряємо counters (1 легкий запит)
            # Якщо немає непрочитаних - не завантажуємо чати взагалі
            counters_data = await get_counters(self.access_token, session)
            counters = counters_data.get("data", {})
            active_counters = counters.get("active", {})
            unread_count = active_counters.get("unread", 0)
            
            # Якщо немає непрочитаних повідомлень - повертаємо порожній список
            if unread_count == 0:
                return []
            
            # КРИТИЧНА ОПТИМІЗАЦІЯ 2: Отримуємо список чатів (1 запит замість N)
            # У списку вже є поле messages з останніми повідомленнями!
            unread_data = await get_conversations(self.access_token, session, unread=1)
            unread_conversations = unread_data.get("data", [])
            
            # ОПТИМІЗАЦІЯ: Якщо є непрочитані - не перевіряємо прочитані (економія запитів)
            # Перевіряємо прочитані тільки якщо counters показує unread, але список порожній
            if not unread_conversations and unread_count > 0:
                # Рідкісний випадок - перевіряємо прочитані
                read_data = await get_conversations(self.access_token, session, unread=0)
                unread_conversations = read_data.get("data", [])
            
            if not unread_conversations:
                return []
            
            # ОБРОБКА БЕЗ ДОДАТКОВИХ ЗАПИТІВ - використовуємо дані зі списку чатів
            for conv in unread_conversations:
                conv_id = conv.get("id", "")
                if not conv_id:
                    continue
                
                # Використовуємо messages зі списку чатів (не робимо окремий запит!)
                messages_list = conv.get("messages", [])
                if not messages_list:
                    continue
                
                # Перевіряємо чи є нові повідомлення
                current_message_ids = {
                    msg.get("id", "") 
                    for msg in messages_list 
                    if msg.get("id")
                }
                last_ids = self.last_message_ids.get(conv_id, set())
                
                # Якщо чат не був ініціалізований - ініціалізуємо його (всі повідомлення вважаються вже баченими)
                if not last_ids:
                    self.last_message_ids[conv_id] = current_message_ids
                    continue
                
                new_ids = current_message_ids - last_ids
                
                if new_ids:
                    # Знаходимо нові повідомлення
                    for msg in messages_list:
                        msg_id = msg.get("id", "")
                        if msg_id in new_ids:
                            # Перевіряємо чи це не наше повідомлення
                            msg_user_id = msg.get("user_id")
                            conversation_user_id = conv.get("user_id")
                            
                            if msg_user_id != conversation_user_id:
                                # ОПТИМІЗАЦІЯ: Зберігаємо тільки необхідні дані для економії пам'яті
                                new_messages.append({
                                    "conversation_id": conv_id,
                                    "message": {
                                        "id": msg.get("id"),
                                        "text": msg.get("text"),
                                        "user_id": msg.get("user_id"),
                                        "created_at": msg.get("created_at")
                                    },
                                    "conversation": {
                                        "id": conv.get("id"),
                                        "user_id": conv.get("user_id"),
                                        "ad": conv.get("ad", {}),
                                        "respondent": conv.get("respondent", {})
                                    }
                                })
                    
                    # Оновлюємо останні ID - об'єднуємо старі та нові ID (щоб не втратити старі)
                    self.last_message_ids[conv_id] = last_ids | current_message_ids
            
        except Exception as e:
            print(f"{thread_prefix}Помилка перевірки: {e}")
        
        return new_messages
    
    def print_message(self, msg_data: Dict):
        """Виводить повідомлення в консоль"""
        conversation = msg_data["conversation"]
        message = msg_data["message"]
        conversation_id = msg_data["conversation_id"]
        
        ad_title = conversation.get("ad", {}).get("title", "Без назви")
        respondent = conversation.get("respondent", {})
        respondent_name = respondent.get("name", "Невідомий")
        msg_text = message.get("text", "")
        msg_time = message.get("created_at", "")
        
        # Форматуємо час
        try:
            if msg_time:
                dt = datetime.fromisoformat(msg_time.replace('Z', '+00:00'))
                time_str = dt.strftime("%Y-%m-%d %H:%M:%S")
            else:
                time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        except:
            time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        print("\n" + "=" * 60)
        print(f"[{time_str}] НОВЕ ПОВІДОМЛЕННЯ")
        print("=" * 60)
        print(f"Оголошення: {ad_title}")
        print(f"Від: {respondent_name}")
        print(f"Текст: {msg_text}")
        print(f"Conversation ID: {conversation_id}")
        print("=" * 60)
    
    async def run(self):
        """Запускає цикл моніторингу"""
        self.running = True
        connector = create_connector()
        thread_prefix = f"[Потік {self.thread_id}] " if self.thread_id is not None else "[Моніторинг] "
        
        async with aiohttp.ClientSession(connector=connector) as session:
            # Ініціалізація
            if not self.initialized:
                await self.initialize(session)
            
            if not self.short_output:
                print(f"\n{thread_prefix}Запущено моніторинг повідомлень...")
                print(f"{thread_prefix}Натисніть Ctrl+C для зупинки\n")
            
            while self.running:
                try:
                    new_messages = await self.check_new_messages(session)
                    
                    if new_messages:
                        if self.short_output:
                            # Короткий вивід для тестування навантаження
                            print(f"{thread_prefix}Знайдено {len(new_messages)} нових повідомлень")
                        else:
                            for msg_data in new_messages:
                                self.print_message(msg_data)
                    
                    await asyncio.sleep(self.check_interval)
                    
                except KeyboardInterrupt:
                    if not self.short_output:
                        print(f"\n{thread_prefix}Зупинка моніторингу...")
                    self.running = False
                    break
                except Exception as e:
                    print(f"{thread_prefix}Помилка: {e}")
                    await asyncio.sleep(self.check_interval)


async def run_monitor_thread(thread_id: int, access_token: str, short_output: bool = True, delay: float = 0.0):
    """
    Запускає один потік моніторингу
    
    Args:
        thread_id: ID потоку
        access_token: Bearer токен
        short_output: Використовувати короткий вивід
        delay: Затримка перед ініціалізацією потоку (в секундах)
    """
    # Затримка перед ініціалізацією для зменшення піку навантаження на старті
    if delay > 0:
        await asyncio.sleep(delay)
    
    monitor = MessageMonitor(access_token, thread_id=thread_id, short_output=short_output)
    try:
        await monitor.run()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f"[Потік {thread_id}] Критична помилка: {e}")


async def main():
    """Основна функція для авторизації та моніторингу"""
    username = "tkachtymur@ukr.net"
    password = "Qwertyasdfzaxsc8"
    
    # Запитуємо кількість потоків для тестування навантаження
    threads_input = input("Скільки потоків емулювати? (Enter = 1): ").strip()
    num_threads = 1
    if threads_input:
        try:
            num_threads = int(threads_input)
            if num_threads < 1:
                num_threads = 1
        except ValueError:
            print("⚠️ Невірне значення, використовую 1 потік")
            num_threads = 1
    
    short_output = num_threads > 1  # Короткий вивід тільки для багатьох потоків
    
    print("=" * 60)
    print("Авторизація в OLX (без проксі)")
    print("=" * 60)
    print(f"Логін: {username}")
    if num_threads > 1:
        print(f"Режим тестування: {num_threads} потоків")
    print()
    
    # Перевіряємо чи є валідний токен
    print("Перевіряю наявність валідного токена...")
    tokens = load_token()
    
    if tokens:
        print("✅ Знайдено валідний токен! Авторизація не потрібна.")
        print(f"Access token: {tokens['access_token'][:50]}...")
        if "expires_in" in tokens:
            print(f"Expires in: {tokens['expires_in']} секунд")
    else:
        print("⚠️ Валідний токен не знайдено. Починаю авторизацію...\n")
        
        try:
            tokens = await auth_without_proxy(username, password)
            
            if "access_token" in tokens:
                print("\n" + "=" * 60)
                print("✅ УСПІХ! Авторизація пройшла успішно!")
                print("=" * 60)
                print(f"Access token: {tokens['access_token'][:50]}...")
                if "refresh_token" in tokens:
                    print(f"Refresh token: {tokens['refresh_token'][:50]}...")
                if "expires_in" in tokens:
                    print(f"Expires in: {tokens['expires_in']} секунд")
                
                # Зберігаємо токен
                save_token(tokens, username)
            else:
                print("\n" + "=" * 60)
                print("❌ НЕУСПІХ! Не отримано access_token")
                print("=" * 60)
                print(f"Отримана відповідь: {tokens}")
                print("\n" + "=" * 60)
                input("Натисніть Enter для закриття...")
                return
                
        except Exception as e:
            print("\n" + "=" * 60)
            print("❌ НЕУСПІХ! Помилка авторизації")
            print("=" * 60)
            print(f"Помилка: {e}")
            import traceback
            print("\nДетальна інформація про помилку:")
            traceback.print_exc()
            print("\n" + "=" * 60)
            input("Натисніть Enter для закриття...")
            return
    
    # Запускаємо моніторинг повідомлень
    access_token = tokens.get("access_token")
    if access_token:
        if num_threads == 1:
            # Звичайний режим - один моніторинг
            monitor = MessageMonitor(access_token, short_output=short_output)
            try:
                await monitor.run()
            except KeyboardInterrupt:
                print("\n[Моніторинг] Моніторинг зупинено")
            except Exception as e:
                print(f"\n[Моніторинг] Критична помилка: {e}")
                import traceback
                traceback.print_exc()
        else:
            # Режим тестування - паралельні потоки
            print(f"\n[Тест] Запускаю {num_threads} паралельних потоків...")
            print("[Тест] Натисніть Ctrl+C для зупинки\n")
            
            try:
                # Створюємо список задач для паралельного виконання з затримкою між ініціалізаціями
                # Затримка 50мс (0.05 сек) між стартами потоків для зменшення піку навантаження
                tasks = []
                for i in range(num_threads):
                    delay = i * 0.05  # Кожен наступний потік стартує на 50мс пізніше
                    task = asyncio.create_task(
                        run_monitor_thread(
                            thread_id=i+1, 
                            access_token=access_token, 
                            short_output=short_output,
                            delay=delay
                        )
                    )
                    tasks.append(task)
                
                # Запускаємо всі потоки паралельно (вони самі почнуть з затримкою)
                await asyncio.gather(*tasks)
            except KeyboardInterrupt:
                print("\n[Тест] Зупинка всіх потоків...")
            except Exception as e:
                print(f"\n[Тест] Критична помилка: {e}")
                import traceback
                traceback.print_exc()
    
    print("\n" + "=" * 60)
    input("Натисніть Enter для закриття...")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(main())
