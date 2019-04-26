class FlaskOOBHooks:
    def register_hooks(self):
        def hook(hook_name, context=None):
            hook_method = getattr(self.custom_hooks, hook_name, None)
            if hook_method is not None:
                hook_method(context)

        self.hook = hook
