import os
import re
from pathlib import Path
from src.thirdparty import triageutils as triageutils
from src.thirdparty.mail.pst_parser import PSTParser
from src.thirdparty.mail.mbox_parser import MBOXParser
from src import BasePlugin, Status
from logging import Logger


####
# Analyze differents formats :
# - pst (complete Outlook/M365 export)
# - ost (partial Outlook export / TR)
# - eml (partial txt export)
# - msg (partial txt export)
# - mbox (complete Thunderbird export / Apple Mail)
####
# Different options :
#
####

# Whitespaces: tab, carriage return, newline, vertical tab, form feed.
FORBIDDEN_WHITESPACE_IN_FILENAMES = re.compile("[\t\r\n\v\f]+")
OTHER_FORBIDDEN_FN_CHARACTERS = re.compile('[/\\\\\\?%\\*:\\|"<>\0]')


class Plugin(BasePlugin):
    """
    Mail plugin pour triage
    """

    def __init__(self, conf: dict):
        super().__init__(config=conf)
        self.zip_file = Path(os.path.join(self.upload_dir, conf["archive"]["name"]))
        self.mail_dir = Path(os.path.join(self.upload_dir, self.hostname, "mail"))
        triageutils.create_directory_path(path=self.mail_dir, logger=self.logger)

        self.zip_destination = Path(os.path.join(self.mail_dir, "extract"))
        triageutils.create_directory_path(path=self.zip_destination, logger=self.logger)

        self.mbox_share = Path(os.path.join(self.mail_dir, "mbox"))
        triageutils.create_directory_path(path=self.mbox_share, logger=self.logger)

        self.pst_share = Path(os.path.join(self.mail_dir, "pst"))
        triageutils.create_directory_path(path=self.pst_share, logger=self.logger)

        self.config["general"]["extracted_zip"] = str(self.zip_destination)
        self.update_config_file(data=self.config)

    @triageutils.LOG
    def mail_extract_archive(self, archive: Path, dest: Path, logger: Logger):
        """Extrait tous les fichiers de l'archive ZIP contenant les mails.

        Args:
            archive (Path): chemin complet du fichier ZIP
            dest (Path): chemin complet de décompression de l'archive
        """
        try:
            triageutils.extract_zip_archive(
                archive=archive,
                dest=dest,
                logger=self.logger,
            )
        except Exception as ex:
            self.error(f"[mail_extract_archive] {ex}")
            raise ex

    @triageutils.LOG
    def analyze_pst(self, extrafields: dict, logger: Logger):
        try:
            for _f in triageutils.search_files_by_extension_generator(
                src=self.zip_destination,
                extension="pst",
                logger=self.logger,
            ):
                self.info(f"[analyze_pst] Processing : {_f}")
                runner = PSTParser(
                    pstfile=_f,
                    logstash_url=self.logstash_url,
                    port=self.mail_port,
                    logger=self.logger,
                    extrafields=extrafields,
                    output_dir=self.pst_share,
                    extract_attachments=self.config["run"]["mail"]["attachments"],
                    is_logstash_active=self.is_logstash_active,
                )
                runner.run()
                if self.is_logstash_active:
                    runner.analytics()
        except Exception as ex:
            self.error(f"[analyze_pst] {str(ex)}")
            raise ex

    @triageutils.LOG
    def analyze_mbox(self, extrafields: dict, logger: Logger):
        try:
            for _f in triageutils.search_files_by_extension_generator(
                src=self.zip_destination,
                extension="mbox",
                logger=self.logger,
            ):
                self.info(f"[analyze_mbox] Processing : {_f}")
                runner = MBOXParser(
                    mbox_path=_f,
                    logstash_url=self.logstash_url,
                    port=self.mail_port,
                    logger=self.logger,
                    extrafields=extrafields,
                    output_dir=self.mbox_share,
                    extract_attachments=self.config["run"]["mail"]["attachments"],
                    is_logstash_active=self.is_logstash_active,
                )
                runner.run()
                if self.is_logstash_active:
                    runner.analytics()
        except Exception as ex:
            self.error(f"[analyze_mbox] {str(ex)}")
            # raise ex

    @triageutils.LOG
    def run(self, logger: Logger):
        """Fonction principale qui exécute tout le triage de l'archive mail

        Args:

        Returns:

        """
        try:
            self.update_workflow_status(
                plugin="mail", module="plugin", status=Status.STARTED
            )
            if self.config["run"]["mail"]["attachments"]:
                self.update_workflow_status(
                    plugin="mail", module="attachments", status=Status.STARTED
                )
            extrafields = dict()
            extrafields["csirt"] = dict()
            extrafields["csirt"]["client"] = self.clientname.lower()
            extrafields["csirt"]["hostname"] = self.hostname.lower()
            extrafields["csirt"]["application"] = "mail"
            self.mail_extract_archive(
                archive=self.zip_file, dest=self.zip_destination, logger=self.logger
            )
            self.analyze_mbox(logger=self.logger, extrafields=extrafields)
            self.analyze_pst(logger=self.logger, extrafields=extrafields)
            self.update_workflow_status(
                plugin="mail", module="plugin", status=Status.FINISHED
            )
            if self.config["run"]["mail"]["attachments"]:
                self.update_workflow_status(
                    plugin="mail", module="attachments", status=Status.FINISHED
                )
        except Exception as ex:
            self.logger.error(f"[MAIL] run {str(ex)}")
            self.update_workflow_status(
                plugin="mail", module="plugin", status=Status.ERROR
            )
            if self.config["run"]["mail"]["attachments"]:
                self.update_workflow_status(
                    plugin="mail", module="attachments", status=Status.ERROR
                )
            raise ex
        finally:
            self.info("[MAIL] End processing")
