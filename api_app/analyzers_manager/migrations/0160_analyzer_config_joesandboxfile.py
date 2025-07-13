from django.db import migrations
from django.db.models.fields.related_descriptors import (
    ForwardManyToOneDescriptor,
    ForwardOneToOneDescriptor,
    ManyToManyDescriptor,
    ReverseManyToOneDescriptor,
    ReverseOneToOneDescriptor,
)

plugin = {
    "python_module": {
        "health_check_schedule": None,
        "update_schedule": None,
        "module": "joesandbox_file.JoeSandboxFile",
        "base_path": "api_app.analyzers_manager.file_analyzers",
    },
    "name": "JoeSandboxFile",
    "description": "[JoeSandboxFile](https://www.joesandbox.com/) is a comprehensive malware analysis tool, which can be used to perform deep malware analysis, on various platforms such as windows, macos, linux, android.",
    "disabled": False,
    "soft_time_limit": 1000,
    "routing_key": "default",
    "health_check_status": True,
    "type": "file",
    "docker_based": False,
    "maximum_tlp": "RED",
    "observable_supported": [],
    "supported_filetypes": [
        "application/vnd.android.package-archive",
        "application/zip",
        "multipart/x-zip",
        "application/java-archive",
        "application/vnd.microsoft.portable-executable",
        "application/vnd.tcpdump.pcap",
        "application/pdf",
        "application/vnd.ms-excel",
        "application/excel",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "text/csv",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/msword",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.ms-powerpoint",
        "application/vnd.ms-office",
        "application/x-binary",
        "application/x-macbinary",
        "application/mac-binary",
        "application/x-mach-binary",
        "application/x-executable",
        "text/x-java",
    ],
    "run_hash": False,
    "run_hash_type": "",
    "not_supported_filetypes": [],
    "mapping_data_model": {},
    "model": "analyzers_manager.AnalyzerConfig",
}

params = [
    {
        "python_module": {
            "module": "joesandbox_file.JoeSandboxFile",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "url",
        "type": "str",
        "description": "URL for your JoeSandbox Instance.",
        "is_secret": False,
        "required": True,
    },
    {
        "python_module": {
            "module": "joesandbox_file.JoeSandboxFile",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "system_to_use",
        "type": "str",
        "description": 'System to use for analysis. Defaults to "lnxubuntu20". Read the Intelowl Usage docs, to get more info. on what systems are available.',
        "is_secret": False,
        "required": False,
    },
    {
        "python_module": {
            "module": "joesandbox_file.JoeSandboxFile",
            "base_path": "api_app.analyzers_manager.file_analyzers",
        },
        "name": "api_key",
        "type": "str",
        "description": "API key for JoeSandbox Instance.",
        "is_secret": True,
        "required": True,
    },
]

values = []


def _get_real_obj(Model, field, value):
    def _get_obj(Model, other_model, value):
        if isinstance(value, dict):
            real_vals = {}
            for key, real_val in value.items():
                real_vals[key] = _get_real_obj(other_model, key, real_val)
            value = other_model.objects.get_or_create(**real_vals)[0]
        # it is just the primary key serialized
        else:
            if isinstance(value, int):
                if Model.__name__ == "PluginConfig":
                    value = other_model.objects.get(name=plugin["name"])
                else:
                    value = other_model.objects.get(pk=value)
            else:
                value = other_model.objects.get(name=value)
        return value

    if (
        type(getattr(Model, field))
        in [
            ForwardManyToOneDescriptor,
            ReverseManyToOneDescriptor,
            ReverseOneToOneDescriptor,
            ForwardOneToOneDescriptor,
        ]
        and value
    ):
        other_model = getattr(Model, field).get_queryset().model
        value = _get_obj(Model, other_model, value)
    elif type(getattr(Model, field)) in [ManyToManyDescriptor] and value:
        other_model = getattr(Model, field).rel.model
        value = [_get_obj(Model, other_model, val) for val in value]
    return value


def _create_object(Model, data):
    mtm, no_mtm = {}, {}
    for field, value in data.items():
        value = _get_real_obj(Model, field, value)
        if type(getattr(Model, field)) is ManyToManyDescriptor:
            mtm[field] = value
        else:
            no_mtm[field] = value
    try:
        o = Model.objects.get(**no_mtm)
    except Model.DoesNotExist:
        o = Model(**no_mtm)
        o.full_clean()
        o.save()
        for field, value in mtm.items():
            attribute = getattr(o, field)
            if value is not None:
                attribute.set(value)
        return False
    return True


def migrate(apps, schema_editor):
    Parameter = apps.get_model("api_app", "Parameter")
    PluginConfig = apps.get_model("api_app", "PluginConfig")
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    if not Model.objects.filter(name=plugin["name"]).exists():
        exists = _create_object(Model, plugin)
        if not exists:
            for param in params:
                _create_object(Parameter, param)
            for value in values:
                _create_object(PluginConfig, value)


def reverse_migrate(apps, schema_editor):
    python_path = plugin.pop("model")
    Model = apps.get_model(*python_path.split("."))
    Model.objects.get(name=plugin["name"]).delete()


class Migration(migrations.Migration):
    atomic = False
    dependencies = [
        ("api_app", "0071_delete_last_elastic_report"),
        ("analyzers_manager", "0159_analyzer_config_expandurl"),
    ]

    operations = [migrations.RunPython(migrate, reverse_migrate)]
