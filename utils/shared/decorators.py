import time
from functools import wraps
from .loader import Loader
# from loader import Loader


class CustomDecorators:
    """Calculate the time taken to execute a function"""

    total_time = 0
    last_execution_time = 0
    _loader_active = False

    @staticmethod
    def measure_execution_time(func):
        """Measure the time taken to execute a function"""
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            result = func(*args, **kwargs)
            end_time = time.time()
            execution_time = end_time - start_time
            # Track time against the concrete class that owns the method.
            # This avoids writing into CustomDecorators.total_time while reads happen
            # from a subclass (which would show 0s in output).
            target_cls = CustomDecorators
            if args:
                owner = args[0]
                if isinstance(owner, CustomDecorators):
                    target_cls = owner.__class__
            target_cls.last_execution_time = execution_time
            target_cls.total_time = getattr(target_cls, "total_time", 0) + execution_time
            # print(f"Execution time for {func.__name__}: {execution_time:.4f} seconds")
            return result
        return wrapper

    @classmethod
    def with_loader(cls,
                    desc: str,
                    end: str,
                    spinner_type: str = "dots",
                    timer: int = 10):
        def decorator(func):
            @wraps(func)
            def wrapper(*args, **kwargs):
               # Start loader only if it is not already active
                if not cls._loader_active:
                    loader = Loader(
                        desc=desc,
                        end=end,
                        spinner_type=spinner_type,
                        timer=timer
                    )
                    cls._loader_active = True
                    try:
                        loader.start()  # Start the loader
                        result = func(*args, **kwargs)  # Execute the function
                        return result
                    finally:
                        loader.stop()  # Stop the loader
                        cls._loader_active = False
                else:
                    # Execute function without starting the loader again
                    return func(*args, **kwargs)
            return wrapper
        return decorator

    @classmethod
    def print_total_time(cls, message="Total execution time:"):
        """Print the total time taken to execute all functions"""
        print(f"\n{message} {cls._humanize_duration(cls.total_time)}")

    @classmethod
    def print_last_execution_time(cls, message="Execution time:"):
        """Print time taken by the most recent decorated call."""
        print(f"\n{message} {cls._humanize_duration(cls.last_execution_time)}")

    @staticmethod
    def format_time(time_in_seconds):
        """Format the time in seconds to hours, minutes and seconds"""
        time_in_seconds = round(time_in_seconds)
        hours, remainder = divmod(time_in_seconds, 3600)
        minutes, seconds = divmod(remainder, 60)
        return hours, minutes, seconds

    @classmethod
    def _humanize_duration(cls, time_in_seconds: float) -> str:
        """Convert duration to human-readable text."""
        hours, minutes, seconds = cls.format_time(time_in_seconds)

        def format_unit(unit: int, label: str) -> str:
            return f"{unit} {label}" if unit == 1 else f"{unit} {label}s"

        if seconds and not (minutes or hours):
            return format_unit(seconds, "second")
        if seconds and minutes and not hours:
            return f"{format_unit(minutes, 'minute')} and {format_unit(seconds, 'second')}."
        if minutes and not (hours or seconds):
            return format_unit(minutes, "minute")
        if hours and not (minutes or seconds):
            return format_unit(hours, "hour")
        if hours and minutes and not seconds:
            return f"{format_unit(hours, 'hour')} and {format_unit(minutes, 'minute')}"
        if hours and seconds and not minutes:
            return f"{format_unit(hours, 'hour')} and {format_unit(seconds, 'second')}."
        if hours or minutes or seconds:
            return (
                f"{format_unit(hours, 'hour')}, "
                f"{format_unit(minutes, 'minute')} and "
                f"{format_unit(seconds, 'second')}"
            )
        if time_in_seconds > 0:
            return f"{time_in_seconds:.2f} seconds"
        return "0 seconds"

    @classmethod
    def reset_total_time(cls):
        """Reset the total time to 0"""
        # global total_time
        cls.total_time = 0
        cls.last_execution_time = 0


if __name__ == "__main__":
    decorator = CustomDecorators()

    decorator.print_total_time()
