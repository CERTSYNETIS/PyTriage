import docker
from logging import Logger


class WrapperDocker:
    """
    Class to manage docker executions
    """

    def __init__(
        self,
        logger: Logger,
    ) -> None:
        self.logger: Logger = logger
        self._docker = docker.from_env()
        self._image: str = ""
        self._container_name: str = ""
        self._volumes: list = list()

    @property
    def image(self):
        return self._image

    @image.setter
    def image(self, name: str):
        self._image = name

    @property
    def container(self):
        return self._container_name

    @container.setter
    def container(self, name: str):
        self._container_name = name

    @property
    def volumes(self):
        return self._volumes

    @volumes.setter
    def volumes(self, volumes: list):
        self._volumes = volumes

    def execute_cmd(self, cmd: list, debug: bool = False) -> bool:
        try:
            if not self._image or not self._volumes or not self._container_name:
                raise Exception("image or volumes or container is not set")
            self.logger.info("Start Docker")
            container = self._docker.containers.run(
                image=self._image,
                auto_remove=True,
                detach=True,
                command=cmd,
                volumes=self._volumes,
                network_mode="host",
                stderr=True,
                stdout=True,
                name=self._container_name,
            )
            if debug:
                for line in container.logs(stream=True):
                    self.logger.info(line)
            container.wait()
            self.logger.info("End Docker")
            return True
        except Exception as ex:
            self.logger.error(f"[execute_cmd] {ex}")
            return False

    def execute_cmd_generator(self, cmd: list):
        try:
            self.logger.info("Start Docker")
            container = self._docker.containers.run(
                image=self._image,
                auto_remove=True,
                detach=True,
                command=cmd,
                volumes=self._volumes,
                network_mode="host",
                stderr=True,
                stdout=True,
                name=self._container_name,
            )
            for line in container.logs(stream=True):
                yield line.decode().strip()
            self.logger.info("End Docker")
        except Exception as ex:
            print(f"[execute_cmd_generator] {ex}")

    def kill_containers_by_name(self, name: str) -> bool:
        try:
            for container in self._docker.containers.list():
                if name in container.name:
                    self.logger.info(
                        f"[kill_containers_by_name] Delete container: {container.name}"
                    )
                    container.kill()
            self._docker.close()
            return True
        except Exception as ex:
            self.logger.error(f"[kill_containers_by_name] {ex}")
            return False

    def kill_container(self, name: str) -> bool:
        try:
            for container in self._docker.containers.list():
                if self._container_name == container.name:
                    self.logger.info(f"Delete container: {container.name}")
                    container.kill()
            self._docker.close()
            return True
        except Exception as ex:
            self.logger.error(f"[kill_containers_by_name] {ex}")
            return False

    def is_image_present(
        self,
        name: str,
    ) -> bool:
        try:
            all_images = []
            for image in self._docker.images.list():
                for key, value in image.attrs.items():
                    if key == "RepoTags":
                        all_images.extend(value)
            if name in all_images:
                return True
            else:
                return False
        except Exception as ex:
            self.logger.error(f"[is_image_present] {ex}")
            raise ex

    def pull_image(self, name: str, tag: str):
        try:
            self._docker.images.pull(repository=name, tag=tag)
        except Exception as ex:
            self.logger.error(f"[pull_image] {ex}")
            raise ex
