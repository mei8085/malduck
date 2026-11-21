Static configuration extractor engine
=====================================

.. automodule:: malduck.extractor

Module interface
----------------

.. autoclass:: malduck.extractor.Extractor
    :members:
    :inherited-members:
.. autoclass:: malduck.extractor.ExtractManager
    :members:
.. autoclass:: malduck.extractor.ExtractorModules
    :members:

Internally used classes and routines
------------------------------------

.. autoclass:: malduck.extractor.extract_manager.ExtractionContext
    :members:

Cross-dump configuration merging
--------------------------------

Configurations ripped from multiple memory dumps of the same family are
merged with provenance tracking instead of replacing one another. Equivalent
fields are unified; contradictory values, type inconsistencies, decoy
configurations and observations without a source are retained on the merged
object with a review status and per-value confidence, while
:attr:`ExtractManager.config` keeps returning only the fields safe to feed
into subsequent decryption and analysis steps.

.. autoclass:: malduck.extractor.config_merger.MergedConfig
    :members:
.. autoclass:: malduck.extractor.config_merger.MergedField
    :members:
.. autoclass:: malduck.extractor.config_merger.FieldValue
    :members:
.. autoclass:: malduck.extractor.config_merger.ConfigSource
    :members:
.. autoclass:: malduck.extractor.config_merger.FieldStatus
    :members:
.. autofunction:: malduck.extractor.config_merger.merge_configs

