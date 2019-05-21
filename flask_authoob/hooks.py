class FlaskOOBHooks:
    def register_hooks(self):
        def hook(hook_name, context):
            hook_method = getattr(self.custom_hooks, hook_name, None)
            if hook_method is not None:
                return hook_method(context)

        self.hook = hook
