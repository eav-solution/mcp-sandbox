import time
import threading
from mcp_sandbox.utils.config import logger

class PeriodicTaskManager:
    """Manager for periodic background tasks"""
    
    @staticmethod
    def start_task(task_func, interval_seconds: int, task_name: str) -> None:
        """Start a background periodic task"""
        def periodic_runner():
            while True:
                try:
                    task_func()
                    time.sleep(interval_seconds)
                except Exception as e:
                    logger.error(f"{task_name} task error: {e}")
        
        task_thread = threading.Thread(target=periodic_runner, daemon=True)
        task_thread.start()
        logger.info(f"Started {task_name} task")

    @staticmethod
    def start_file_cleanup(cleanup_func) -> None:
        """Start background task for periodic file cleanup"""
        PeriodicTaskManager.start_task(cleanup_func, 600, "automatic file cleanup") 

    @staticmethod
    def start_container_cleanup(cleanup_func, interval_seconds: int = 300) -> None:
        """Start background task for periodic container cleanup"""
        PeriodicTaskManager.start_task(
            cleanup_func, interval_seconds, "automatic container cleanup"
        )