import os
import logging
import hashlib
from time import time, gmtime, strftime

from zeep import Client, Settings

from prometheus_client import (generate_latest, PROCESS_COLLECTOR, 
    PLATFORM_COLLECTOR, GC_COLLECTOR)
from prometheus_client.core import REGISTRY, GaugeMetricFamily

class Collector(object):
    """ Kaspersky DDoS Prevention metrics exporter """    
    def __init__(self):

        logging.basicConfig(level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        self.logger = logging.getLogger(type(self).__name__)

        self.metrics = []

        try:
            kdp_url = os.environ['KDP_URL']
            self.kdp_client_id = int(os.environ['KDP_CLIENT_ID'])
            self.kdp_user_id = int(os.environ['KDP_USER_ID'])
            self.kdp_secret_key = os.environ['KDP_SECRET_KEY']
            self.resource_name = os.environ['KDP_RESOURCE']
            #идентификатор локали (10 - для английского, 77 - для русского)
            self.locale_id = 10

            self.client = Client(wsdl=kdp_url)
        except Exception as e:
            self.logger.fatal(f'Failed to initialize config: {e}')
            return


    def collect(self):
        """ Metrics collection """

        if self.ping() == False:
            #continue even if ping was failed
            #return
            self.logger.warn('Skipping the API availability check')

        self.get_api_version()
        self.client_resource_list()    
        plist = self.get_measured_parameter_list()
        pdata = self.get_measured_parameter_data()
        self.measured_parameters(plist, pdata)

        self.get_protocol_ratio()
        self.get_resource_geo_ratio()
        self.get_resource_new_ip_blocks()    
        self.get_resource_anomaly_list()
        self.attack_active_list()    

        for m in self.metrics:
            yield m


    def generate_latest_scrape(self):
        """ Return a content of Prometheus registry """
        return generate_latest(REGISTRY)    


    def authenticate(self, method, *args):    
        """
        Для формирования подписи необходимо конкатенировать:
        1. ID клиента
        2. ID пользователя
        3. Название вызываемого метода
        4. Аргументы вызываемого метода в порядке, совпадающем с его объявлением. Используются только
        простые аргументы, структуры пропускаются
        5. SecretKey, который задается в настройках и известен только клиенту и системе
        6. Системное время (unixtime), округленное до 600 секунд в меньшую сторону.
        От полученной в результате конкатенации строки необходимо вычислить md5. MD5 хэш записывается
        в виде шестнадцатеричной строки в нижнем регистре (32 символа) и передается в структуре
        ClientAuth с именем Auth. Требуется, чтобы системное время на клиентах не отличалось от точного
        времени на величину большую 600 секунд. В противном случае аутентификация будет неуспешной.
        В случае ошибки сервис может генерировать исключение SOAP Fault c поясняющим текстом.
        """
        arg_list = ''
        unix_time = int(600 * (int(round(time() / 600,0))))

        for arg in args:
            arg_list = arg_list + str(arg)

        msg = f'{self.kdp_client_id}{self.kdp_user_id}{method}{arg_list}'
        msg = f'{msg}{self.kdp_secret_key}{unix_time}'
        msg_hash = hashlib.md5(bytes(msg,'utf-8')).hexdigest()
        
        auth = self.client.get_type('ns1:ClientAuth')
        clientAuth = auth(client_id=self.kdp_client_id, 
            user_id=self.kdp_user_id, 
            hash=msg_hash
        )
        self.logger.debug(f'Auth for {method} is: {clientAuth}')                
        return clientAuth


    def ping(self):
        """       
        Описание: метод предназначен для проверки связи (корректности работы) 
        транспорта между клиентом и API
        Входные параметры:
            нет
        Результат:
            1, или Soap Fault в случае ошибки
        """
        try:
            result = self.client.service.ping()
            assert result

            if result == 1:
                self.logger.info('KDP API is available')
                return True
            else:
                self.logger.error('KDP API is unavailable')
                return False
        except Exception as e:
            self.logger.error(f'Failed to ping KDP API: {e}')
            return False

    
    def get_api_version(self):
        """
        Описание: вывод текущей версии API-сервера и режима работы
        Входные параметры:
            нет
        Выходные параметры:
            version (str) - версия API-сервера
            mode (str) - режим работы API-сервера (client/admin)
        """
        self.logger.info(f'{self.resource_name}: get_api_version started.')
        
        self.metric_api_version = GaugeMetricFamily('kdp_api_version',
            'Version of KDP API',
            labels=['name','version','mode']
        )
        self.metrics.append(self.metric_api_version)
        
        try:              
            auth = self.authenticate('get_api_version', 'None')
            req = self.client.service.get_api_version(Auth=auth)
            assert req
            self.logger.debug(req)

            self.metric_api_version.add_metric([self.resource_name, 
                req.version, req.mode], 1)

        except Exception as e:
            self.logger.error(f'{self.resource_name}: get_api_version failed with: {e}')            


    def client_resource_list(self):
        """
        Описание: отображение списка ресурсов клиента
        Входные параметры:
            client_id (int) - идентификатор клиента (целое число, от 1 до 4 294 967 295)
            locale_id (int) - идентификатор локали (10 - для английского, 77 - для русского)
            group_id (int,nil) - идентификатор группы ресурсов (целое число, от 1 до 4 294 967 295). 
            Может быть nil, тогда выводится список всех ресурсов клиента
        Выходные параметры:
            id (int) - идентификатор ресурса
            name (str) - название русурса на родном языке
            group_id (int) - идентификатор группы ресурса
            group (str) - название группы ресурсов
            internal_ip (str) - внутренние IP-адреса
            external_ip (str,nil) - внешние IP-адреса
            redirection_method_name (str) - тип перенаправления трафика (bgp/dns)
        Примечание:
            Внутренние и внешние адреса выводятся диапазонами, через дефисы и запятые.
            Отображается не более трёх “видимых” IP, и при необходимости, 
            количество неотображаемых адресов.
            Пример: 1.1.1.2-1.1.1.4, 1.1.1.7 . . . (+12)            
        """
        self.logger.info(f'{self.resource_name}: client_resource_list started.')
        self.metric_client_resource = GaugeMetricFamily(
            'kdp_client_resource',
            'Client resources',
            labels=['name','group','internal_ip','external_ip',
                'redirection_method'])
        self.metrics.append(self.metric_client_resource)

        try:
            auth = self.authenticate('client_resource_list',
                self.kdp_client_id,
                self.locale_id,
                'None'
            )
            req = self.client.service.client_resource_list(Auth=auth,
                client_id=self.kdp_client_id,
                locale_id=self.locale_id
            )
            assert req
            self.logger.debug(req)

            for i in req:
                if i.name == self.resource_name:
                    self.resource_id = i.id

                    self.metric_client_resource.add_metric([
                        i.name,
                        i.group,
                        i.internal_ip,
                        i.external_ip,
                        i.redirection_method_name], 1)            

        except Exception as e:
            self.logger.error(f'{self.resource_name}: client_resource_list failed with: {e}')


    def get_protocol_ratio(self):
        """
        Описание: соотношнение протоколов в трафике для каждой минуты указанного интервала
        Входные параметры:
            client_id (int) - идентификатор клиента (целое число, от 1 до 4 294 967 295)
            locale_id (int) - идентификатор локали (10 - для английского, 77 - для русского)
            resource_id (int) - идентификатор ресурса (целое число, от 1 до 4 294 967 295)
            start (str) - начало интервала, за который выводить данные (‘YYYY-MM-DD hh:mm:ss’)
            end (str,nil) - конец интервала, за который выводить данные (‘YYYY-MM-DD hh:mm:ss’, конец
            интервала не должен быть меньше начала интервала). Может быть nil, тогда берётся текущий
            момент времени
        Примечание: максимальный интервал времени - 1 день.
        Выходные параметры:
            point (list) - массив точек, содержащие минуты времени, для каждой 
            из которых отображаются протоколы со значениями для чистого трафика
            timestamp (str) - минута, для которой отображаются протоколы
            elements (list) - протоколы со значениями для чистого трафика
            protocol (str) - протокол, для которого отображается значение
            value (str) - доля трафика этого протокола в общем трафике ресурса за эту минуту
        """
        self.logger.info(f'{self.resource_name}: get_protocol_ratio started.')                    
        try:
            start_time=strftime('%Y-%m-%d %H:%M:%S',gmtime(time()-60*5))
            end_time=strftime('%Y-%m-%d %H:%M:%S',gmtime(time()))
            auth = self.authenticate('get_protocol_ratio',
                self.kdp_client_id,
                self.locale_id,
                self.resource_id,
                start_time,
                end_time
            )
            req = self.client.service.get_protocol_ratio(Auth=auth,
                client_id=self.kdp_client_id,
                locale_id=self.locale_id,
                resource_id=self.resource_id,
                start=start_time,
                end=end_time
            )
            assert req
            self.logger.debug(req)

        except Exception as e:
            self.logger.error(f'{self.resource_name}: get_protocol_ratio failed with: {e}')


    def get_resource_geo_ratio(self):
        """
        get_resource_geo_ratio(Auth, client_id, locale_id, resource_id)
        Описание: географическое распределение трафика за последние пять минут
        Входные параметры:
            client_id (int) - идентификатор клиента (целое число, от 1 до 4 294 967 295)
            locale_id (int) - идентификатор локали (10 - для английского, 77 - для русского)
            resource_id (int) - идентификатор ресурса (целое число, от 1 до 4 294 967 295)
        Выходные параметры:
            country (str) - название страны в указанной локали
            value (str) - доля IP-адресов из этой страны во входящем трафике 
            ресурса за последние пять минут
        """
        self.logger.info(f'{self.resource_name}: get_resource_geo_ratio started.')
        
        self.metric_resource_geo_ratio_prc = GaugeMetricFamily(
            'kdp_resource_geo_ratio_prc',
            'Requests by Country. Ratio.',
            labels=['name','country'])
        self.metrics.append(self.metric_resource_geo_ratio_prc)

        try:
            auth = self.authenticate('get_resource_geo_ratio',
                self.kdp_client_id,
                self.locale_id,
                self.resource_id
            )
            req = self.client.service.get_resource_geo_ratio(Auth=auth,
                client_id=self.kdp_client_id,
                locale_id=self.locale_id,
                resource_id=self.resource_id
            )
            assert req
            self.logger.debug(req)

            for i in req:
                self.metric_resource_geo_ratio_prc.add_metric([
                    self.resource_name, i.country], i.value)

        except Exception as e:
            self.logger.error(f'{self.resource_name}: get_resource_geo_ratio failed with: {e}')


    def get_measured_parameter_list(self):
        """
        Описание: вывести список видимых клиенту измеряемых параметров, настроенных для данного
        ресурса
        Входные параметры:
            client_id (int) - идентификатор клиента (целое число, от 1 до 4 294 967 295)
            locale_id (int) - идентификатор локали (10 - для английского, 77 - для русского)
            resource_id (int) - идентификатор ресурса (целое число, от 1 до 4 294 967 295)
        Выходные параметры:
            id (int) - идентификатор экземпляра измеряемого параметра
            short_name (str) - короткое имя измеряемого параметра
            description (str) - описание измеряемого параметра
            unit_type_name (str) - единицы измерения измеряемого параметра (например, Бит/с)
            direction (int) - направление пересечения порога экземпляра 
            измеряемого параметра (вверх = 1, вниз = -1)
            parent_id (int) - для построения дерева
            check_id (int) - измеряемый параметр, из которого был сделан конкретный экземпляр
            is_favourite (str) - “любимые” измеряемые параметры (выводятся в отчетах)
        """
        self.logger.info(f'{self.resource_name}: get_measured_parameter_list started.')        
        try:
            auth = self.authenticate('get_measured_parameter_list',
                self.kdp_client_id,
                self.locale_id,
                self.resource_id
            )
            req = self.client.service.get_measured_parameter_list(Auth=auth,
                client_id=self.kdp_client_id,
                locale_id=self.locale_id,
                resource_id=self.resource_id
            )
            assert req
            self.logger.debug(req)
            
            return req

        except Exception as e:
            self.logger.error(f'{self.resource_name}: get_measured_parameter_list failed with: {e}')
            return None 


    def get_measured_parameter_data(self):
        """Описание: вывести массив всех значений видимых клиенту измеряемых параметров, настроенных
        для данного ресурса
        Входные параметры:
            client_id (int) - идентификатор клиента (целое число, от 1 до 4 294 967 295)
            resource_id (int) - идентификатор ресурса (целое число, от 1 до 4 294 967 295)
            start_time (str) - начало интервала, за который выводить данные (‘YYYY-MM-DD hh:mm:ss’)
            end_time (str) - конец интервала, за который выводить данные (‘YYYY-MM-DD hh:mm:ss’)
            Примечание:
            Максимальный интервал времени - 3 дня.
        Выходные параметры:
            unit_check_id (int) - идентификатор экземпляра измеряемого параметра
            timestamp (str) - точка времени, для которой выводятся значения (таймстамп)
            type (int) - тип линии (2 - “чистый” трафик, 0 - “грязный” трафик)
            value (str) - значение линии
            threshold (str) - “профиль” данного экземпляра измеряемого параметра в данной точке
            mult1 (str) - множитель уровня “внимание”
            mult2 (str) - множитель уровня “тревога”
        """
        self.logger.info(f'{self.resource_name}: get_measured_parameter_data started.')        
        try:
            start_time=strftime('%Y-%m-%d %H:%M:%S',gmtime(time()-60*5))
            end_time=strftime('%Y-%m-%d %H:%M:%S',gmtime(time()))
            auth = self.authenticate('get_measured_parameter_data',
                self.kdp_client_id,
                self.resource_id,
                start_time,
                end_time
            )
            req = self.client.service.get_measured_parameter_data(Auth=auth,
                client_id=self.kdp_client_id,
                resource_id=self.resource_id,
                start_time=start_time,
                end_time=end_time
            )
            assert req
            self.logger.debug(req)
            
            return req

        except Exception as e:
            self.logger.error(f'{self.resource_name}: get_measured_parameter_data failed with: {e}')
            return None


    def get_resource_new_ip_blocks(self):
        """
        Описание: вывести количество новых блокировок IP-адресов для каждой минуты указанного
        интервала
        Входные параметры:
            client_id (int) - идентификатор клиента (целое число, от 1 до 4 294 967 295)
            resource_id (int) - идентификатор ресурса (целое число, от 1 до 4 294 967 295)
            start_time (str) - начало интервала, за который выводить данные (‘YYYY-MM-DD hh:mm:ss’)
            end_time (str,nil) - конец интервала, за который выводить данные (‘YYYY-MM-DD hh:mm:ss’,
            конец интервала не должен быть меньше начала интервала). Может быть nil, тогда берётся
            текущий момент времени
        Примечание: 
            максимальный интервал времени - 3 дня.
        Выходные параметры:
            timestamp (str) - точка времени
            new_ip_blocks (int) - количество новых блокировок IP-адресов
        """
        self.logger.info(f'{self.resource_name}: get_resource_new_ip_blocks started.')

        self.metric_resource_new_ip_blocks_count = GaugeMetricFamily(
            'kdp_resource_new_ip_blocks_count',
            'Count of new IP blocked. Count.',
            labels=['name'])
        self.metrics.append(self.metric_resource_new_ip_blocks_count)

        try:
            start_time=strftime('%Y-%m-%d %H:%M:%S',gmtime(time()-60*5))
            end_time=strftime('%Y-%m-%d %H:%M:%S',gmtime(time()))
            auth = self.authenticate('get_resource_new_ip_blocks',
                self.kdp_client_id,
                self.resource_id,
                start_time,
                end_time
            )
            req = self.client.service.get_resource_new_ip_blocks(Auth=auth,
                client_id=self.kdp_client_id,
                resource_id=self.resource_id,
                start_time=start_time,
                end_time=end_time
            )
            assert req
            self.logger.debug(req)

            for i in req:
                self.metric_resource_new_ip_blocks_count.add_metric([
                    self.resource_name], i.new_ip_blocks)

        except Exception as e:
            self.logger.error(f'{self.resource_name}: get_resource_new_ip_blocks failed with: {e}')   
      

    def get_resource_anomaly_list(self):
        """
        Описание: список аномалий по видимым клиенту измеряемым параметрам, настроенным для
        данного ресурса
        Входные параметры:
            client_id (int) - идентификатор клиента (целое число, от 1 до 4 294 967 295)
            locale_id (int) - идентификатор локали (10 - для английского, 77 - для русского)
            resource_id (int) - идентификатор ресурса (целое число, от 1 до 4 294 967 295)
            start (str) - начало интервала, за который выводить данные (‘YYYY-MM-DD hh:mm:ss’)
            end (str,nil) - конец интервала, за который выводить данные (‘YYYY-MM-DD hh:mm:ss’, конец
            интервала не должен быть меньше начала интервала). Может быть nil, тогда берётся текущий
            момент времени
            limit (int,nil) - количество отображаемых записей (целое число, от 1 до 1000). Может быть nil,
            тогда приравнивается 1000
            offset (int,nil) - количество пропускаемых записей (целое число, от 0 до 4 294 967 295). Может
            быть nil, тогда приравнивается 0
            Примечание: максимальный интервал времени - 1 день.
        Выходные параметры:
            id (int) - идентификатор аномалии в системе
            color (int) - цвет/уровень аномалии (0 - зелёный, 1 - жёлтый/внимание, 2 - красный/тревога)
            start (str) - таймстамп начала аномалии
            last (str) - таймстамп последней точки аномалии
            state (str) - является ли аномалия активной (active/recent)
            measured_parameter_id (int) - идентификатор измеряемого параметра
            measured_parameter_type_id (int) - идентификатор типа измеряемого параметра
            measured_parameter_short_name (str) - имя измеряемого параметра в указанной локали    
            measured_parameter_units (str) - единицы измерения параметра в указанной локали
            measured_parameter_direction (str) - направление пересечения профиля для обнаружения
            аномалий (1: вверх, -1: вниз)
            max_point_timestamp (str) - время пика аномалии
            max_point_value (str) - значение измеряемого параметра в пике
            max_point_threshold (str) - значение профиля обнаружения аномалии в момент пикового
            значения
            max_point_percentage (str) - процент отклонения от значения в пике от профиля обнаружения
        """
        limit=1000
        offset=0

        self.logger.info(f'{self.resource_name}: get_resource_anomaly_list started.')

        self.metric_resource_anomaly_max_value = GaugeMetricFamily(
            'kdp_resource_anomaly_max_value',
            'Anomaly. Value of measured parameter in a max point.',
            labels=['name','parameter','state','color'])
        self.metrics.append(self.metric_resource_anomaly_max_value)
        
        self.metric_resource_anomaly_max_percent = GaugeMetricFamily(
            'kdp_resource_anomaly_max_percent',
            'Anomaly. Percent of deviation in measured parameter.',
            labels=['name','parameter','state','color'])
        self.metrics.append(self.metric_resource_anomaly_max_percent)


        try:
            start_time=strftime('%Y-%m-%d %H:%M:%S',gmtime(time()-60*5))
            end_time=strftime('%Y-%m-%d %H:%M:%S',gmtime(time()))
            auth = self.authenticate('get_resource_anomaly_list',
                self.kdp_client_id,
                self.locale_id,
                self.resource_id,
                start_time,
                end_time,
                limit,
                offset
            )

            req = self.client.service.get_resource_anomaly_list(Auth=auth,
                client_id=self.kdp_client_id,
                locale_id=self.locale_id,
                resource_id=self.resource_id,
                start=start_time,
                end=end_time,
                limit=limit,
                offset=offset
            )
            assert req
            self.logger.debug(req)

            for i in req:
                self.metric_resource_anomaly_max_value.add_metric([
                    self.resource_name, i.measured_parameter_short_name,
                    i.state, str(i.color)], i.max_point_value)
                
                self.metric_resource_anomaly_max_percent.add_metric([
                    self.resource_name, i.measured_parameter_short_name,
                    i.state, str(i.color)], i.max_point_percentage)

        except Exception as e:
            self.logger.error(f'{self.resource_name}: get_resource_anomaly_list failed with: {e}')


    def attack_active_list(self):
        """
        Описание: вывести список всех активных атак на ресурсы клиента
        Входные параметры:
            client_id (int) - идентификатор клиента (целое число, от 1 до 4 294 967 295)
            locale_id (int) - идентификатор локали (10 - для английского, 77 - для русского)
        Выходные параметры:
            attack_id (int) - идентификатор атаки
            attack_type (str) - тип атаки в выбранной локали
            start (str) - таймстамп начала атаки
            resource_id (int) - идентификатор ресурса
            resource_name (str) - имя ресурса в выбранной локали
            group_id (int) - идентификатор группы ресурса
            group_name (str) - имя группы ресурса
            max_point_value_bps (float) - значение измеряемого параметра “Входящий трафик в битах,
            Бит/с” в пике с начала атаки
            max_point_value_pps (float) - значение измеряемого параметра “Входящий трафик в пакетах,
            Пкт/с” в пике с начала атаки
            max_point_value_rps (float) - значение измеряемого параметра “HTTP-запросы, Шт/мин” в
            пике с начала атак
        """
        self.logger.info(f'{self.resource_name}: attack_active_list started.')

        self.metric_resource_attack_incoming_traffic_bps = GaugeMetricFamily(
            'kdp_resource_attack_incoming_traffic_bps',
            'Anomaly. Incoming traffic during anomaly. bps.',
            labels=['name','attack_id','attack_type'])
        self.metrics.append(self.metric_resource_attack_incoming_traffic_bps)

        self.metric_resource_attack_incoming_traffic_pps = GaugeMetricFamily(
            'kdp_resource_attack_incoming_traffic_pps',
            'Anomaly. Incoming traffic during anomaly. pps.',
            labels=['name','attack_id','attack_type'])
        self.metrics.append(self.metric_resource_attack_incoming_traffic_pps)

        self.metric_resource_attack_http_rate = GaugeMetricFamily(
            'kdp_resource_attack_http_rate',
            'Anomaly. HTTP requests rate during anomaly. hits/s.',
            labels=['name','attack_id','attack_type'])
        self.metrics.append(self.metric_resource_attack_http_rate)        

        try:
            auth = self.authenticate('attack_active_list',
                self.kdp_client_id,
                self.locale_id
            )
            req = self.client.service.attack_active_list(Auth=auth,
                client_id=self.kdp_client_id,
                locale_id=self.locale_id
            )
            assert req
            self.logger.debug(req)

            for i in req:
                if i.resource_id == self.resource_id:
                    self.metric_resource_attack_incoming_traffic_bps.add_metric([
                        self.resource_name, str(i.attack_id), i.attack_type],
                        i.max_point_value_bps)

                    self.metric_resource_attack_incoming_traffic_pps.add_metric([
                        self.resource_name, str(i.attack_id), i.attack_type],
                        i.max_point_value_pps)

                    self.metric_resource_attack_http_rate.add_metric([
                        self.resource_name, str(i.attack_id), i.attack_type],
                        i.max_point_value_pps)

        except Exception as e:
            self.logger.error(f'{self.resource_name}: attack_active_list failed with: {e}')


    def measured_parameters(self, param_list, param_data):
        
        self.logger.info(f'{self.resource_name}: measured_parameters started.')        
        

        ## Number of IPs
        self.metric_ip_rate_direction = GaugeMetricFamily(
            'kdp_ip_rate_direction',
            'Number of IP addresses. Direction.',
            labels=['resource','type'])
        self.metrics.append(self.metric_ip_rate_direction)            

        self.metric_ip_rate_threshold = GaugeMetricFamily(
            'kdp_ip_rate_threshold',
            'Number of IP addresses. Threshold.',
            labels=['resource','type'])
        self.metrics.append(self.metric_ip_rate_threshold)            

        self.metric_ip_rate_mult1 = GaugeMetricFamily(
            'kdp_ip_rate_mult1',
            'Number of IP addresses. Mult1.',
            labels=['resource','type'])
        self.metrics.append(self.metric_ip_rate_mult1)            

        self.metric_ip_rate_mult2 = GaugeMetricFamily(
            'kdp_ip_rate_mult2',
            'Number of IP addresses. Mult2.',
            labels=['resource','type'])
        self.metrics.append(self.metric_ip_rate_mult2)            

        self.metric_ip_rate = GaugeMetricFamily(
            'kdp_ip_rate',
            'Number of IP addresses. IPs/min.',
            labels=['resource','type'])
        self.metrics.append(self.metric_ip_rate)


        ## Number of incoming TCP packets with SYN flag        
        self.metric_syn_packets_direction = GaugeMetricFamily(
            'kdp_syn_packets_direction',
            'Number of incoming TCP packets with SYN flag. Direction.',
            labels=['resource','type'])
        self.metrics.append(self.metric_syn_packets_direction)            
      
        self.metric_syn_packets_threshold = GaugeMetricFamily(
            'kdp_syn_packets_threshold',
            'Number of incoming TCP packets with SYN flag. Threshold.',
            labels=['resource','type'])
        self.metrics.append(self.metric_syn_packets_threshold)            

        self.metric_syn_packets_mult1 = GaugeMetricFamily(
            'kdp_syn_packets_mult1',
            'Number of incoming TCP packets with SYN flag. Mult1.',
            labels=['resource','type'])
        self.metrics.append(self.metric_syn_packets_mult1)

        self.metric_syn_packets_mult2 = GaugeMetricFamily(
            'kdp_syn_packets_mult2',
            'Number of incoming TCP packets with SYN flag. Mult2.',
            labels=['resource','type'])
        self.metrics.append(self.metric_syn_packets_mult2)            

        self.metric_syn_packets = GaugeMetricFamily(
            'kdp_syn_packets',
            'Number of incoming TCP packets with SYN flag. pps.',
            labels=['resource','type'])
        self.metrics.append(self.metric_syn_packets)            
        

        ## SYN rating
        self.metric_syn_rating_direction = GaugeMetricFamily(
            'kdp_syn_rating_direction',
            'SYN rating. Direction.',
            labels=['resource','type'])
        self.metrics.append(self.metric_syn_rating_direction)                      

        self.metric_syn_rating_threshold = GaugeMetricFamily(
            'kdp_syn_rating_threshold',
            'SYN rating. Threshold.',
            labels=['resource','type'])
        self.metrics.append(self.metric_syn_rating_threshold)            

        self.metric_syn_rating_mult1 = GaugeMetricFamily(
            'kdp_syn_rating_mult1',
            'SYN rating. Mult1.',
            labels=['resource','type'])
        self.metrics.append(self.metric_syn_rating_mult1)

        self.metric_syn_rating_mult2 = GaugeMetricFamily(
            'kdp_syn_rating_mult2',
            'SYN rating. Mult2.',
            labels=['resource','type'])
        self.metrics.append(self.metric_syn_rating_mult2)            

        self.metric_syn_rating = GaugeMetricFamily(
            'kdp_syn_rating',
            'SYN rating. times.',
            labels=['resource','type'])
        self.metrics.append(self.metric_syn_rating)
        

        ## Incoming traffic speed in bits per second
        self.metric_incoming_traffic_bps_direction = GaugeMetricFamily(
            'kdp_incoming_traffic_bps_direction',
            'Incoming traffic speed in bits per second. Direction.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_traffic_bps_direction)                      

        self.metric_incoming_traffic_bps_threshold = GaugeMetricFamily(
            'kdp_incoming_traffic_bps_threshold',
            'Incoming traffic speed in bits per second. Threshold.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_traffic_bps_threshold)            

        self.metric_incoming_traffic_bps_mult1 = GaugeMetricFamily(
            'kdp_incoming_traffic_bps_mult1',
            'Incoming traffic speed in bits per second. Mult1.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_traffic_bps_mult1)

        self.metric_incoming_traffic_bps_mult2 = GaugeMetricFamily(
            'kdp_incoming_traffic_bps_mult2',
            'Incoming traffic speed in bits per second. Mult2.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_traffic_bps_mult2)            

        self.metric_incoming_traffic_bps = GaugeMetricFamily(
            'kdp_incoming_traffic_bps',
            'Incoming traffic speed in bits per second. bps.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_traffic_bps)
        

        ## Incoming traffic speed in packets per second
        self.metric_incoming_traffic_pps_direction = GaugeMetricFamily(
            'kdp_incoming_traffic_pps_direction',
            'Incoming traffic speed in packets per second. Direction.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_traffic_pps_direction)                      

        self.metric_incoming_traffic_pps_threshold = GaugeMetricFamily(
            'kdp_incoming_traffic_pps_threshold',
            'Incoming traffic speed in packets per second. Threshold.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_traffic_pps_threshold)            

        self.metric_incoming_traffic_pps_mult1 = GaugeMetricFamily(
            'kdp_incoming_traffic_pps_mult1',
            'Incoming traffic speed in packets per second. Mult1.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_traffic_pps_mult1)

        self.metric_incoming_traffic_pps_mult2 = GaugeMetricFamily(
            'kdp_incoming_traffic_pps_mult2',
            'Incoming traffic speed in packets per second. Mult2.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_traffic_pps_mult2)            

        self.metric_incoming_traffic_pps = GaugeMetricFamily(
            'kdp_incoming_traffic_pps',
            'Incoming traffic speed in packets per second. pps.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_traffic_pps)
        

        ## Outgoing traffic speed in bits per second
        self.metric_outgoing_traffic_bps_direction = GaugeMetricFamily(
            'kdp_outgoing_traffic_bps_direction',
            'Outgoing traffic speed in bits per second. Direction.',
            labels=['resource','type'])
        self.metrics.append(self.metric_outgoing_traffic_bps_direction)                      

        self.metric_outgoing_traffic_bps_threshold = GaugeMetricFamily(
            'kdp_outgoing_traffic_bps_threshold',
            'Outgoing traffic speed in bits per second. Threshold.',
            labels=['resource','type'])
        self.metrics.append(self.metric_outgoing_traffic_bps_threshold)            

        self.metric_outgoing_traffic_bps_mult1 = GaugeMetricFamily(
            'kdp_outgoing_traffic_bps_mult1',
            'Outgoing traffic speed in bits per second. Mult1.',
            labels=['resource','type'])
        self.metrics.append(self.metric_outgoing_traffic_bps_mult1)

        self.metric_outgoing_traffic_bps_mult2 = GaugeMetricFamily(
            'kdp_outgoing_traffic_bps_mult2',
            'Outgoing traffic speed in bits per second. Mult2.',
            labels=['resource','type'])
        self.metrics.append(self.metric_outgoing_traffic_bps_mult2)            

        self.metric_outgoing_traffic_bps = GaugeMetricFamily(
            'kdp_outgoing_traffic_bps',
            'Outgoing traffic speed in bits per second. bps.',
            labels=['resource','type'])
        self.metrics.append(self.metric_outgoing_traffic_bps)
        

        ## Outgoing traffic speed in packets per second
        self.metric_outgoing_traffic_pps_direction = GaugeMetricFamily(
            'kdp_outgoing_traffic_pps_direction',
            'Outgoing traffic speed in packets per second. Direction.',
            labels=['resource','type'])
        self.metrics.append(self.metric_outgoing_traffic_pps_direction)                      

        self.metric_outgoing_traffic_pps_threshold = GaugeMetricFamily(
            'kdp_outgoing_traffic_pps_threshold',
            'Outgoing traffic speed in packets per second. Threshold.',
            labels=['resource','type'])
        self.metrics.append(self.metric_outgoing_traffic_pps_threshold)            

        self.metric_outgoing_traffic_pps_mult1 = GaugeMetricFamily(
            'kdp_outgoing_traffic_pps_mult1',
            'Outgoing traffic speed in packets per second. Mult1.',
            labels=['resource','type'])
        self.metrics.append(self.metric_outgoing_traffic_pps_mult1)

        self.metric_outgoing_traffic_pps_mult2 = GaugeMetricFamily(
            'kdp_outgoing_traffic_pps_mult2',
            'Outgoing traffic speed in packets per second. Mult2.',
            labels=['resource','type'])
        self.metrics.append(self.metric_outgoing_traffic_pps_mult2)            

        self.metric_outgoing_traffic_pps = GaugeMetricFamily(
            'kdp_outgoing_traffic_pps',
            'Outgoing traffic speed in packets per second. pps.',
            labels=['resource','type'])
        self.metrics.append(self.metric_outgoing_traffic_pps)


        ## Incoming ICMP traffic speed in packets per second
        self.metric_incoming_icmp_traffic_pps_direction = GaugeMetricFamily(
            'kdp_incoming_icmp_traffic_pps_direction',
            'Incoming ICMP traffic speed in packets per second. Direction.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_icmp_traffic_pps_direction)                      

        self.metric_incoming_icmp_traffic_pps_threshold = GaugeMetricFamily(
            'kdp_incoming_icmp_traffic_pps_threshold',
            'Incoming ICMP traffic speed in packets per second. Threshold.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_icmp_traffic_pps_threshold)            

        self.metric_incoming_icmp_traffic_pps_mult1 = GaugeMetricFamily(
            'kdp_incoming_icmp_traffic_pps_mult1',
            'Incoming ICMP traffic speed in packets per second. Mult1.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_icmp_traffic_pps_mult1)

        self.metric_incoming_icmp_traffic_pps_mult2 = GaugeMetricFamily(
            'kdp_incoming_icmp_traffic_pps_mult2',
            'Incoming ICMP traffic speed in packets per second. Mult2.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_icmp_traffic_pps_mult2)            

        self.metric_incoming_icmp_traffic_pps = GaugeMetricFamily(
            'kdp_incoming_icmp_traffic_pps',
            'Incoming ICMP traffic speed in packets per second. pps.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_icmp_traffic_pps)   


        ## Incoming TCP traffic speed in packets per second
        self.metric_incoming_tcp_traffic_pps_direction = GaugeMetricFamily(
            'kdp_incoming_tcp_traffic_pps_direction',
            'Incoming TCP traffic speed in packets per second. Direction.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_tcp_traffic_pps_direction)                      

        self.metric_incoming_tcp_traffic_pps_threshold = GaugeMetricFamily(
            'kdp_incoming_tcp_traffic_pps_threshold',
            'Incoming TCP traffic speed in packets per second. Threshold.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_tcp_traffic_pps_threshold)            

        self.metric_incoming_tcp_traffic_pps_mult1 = GaugeMetricFamily(
            'kdp_incoming_tcp_traffic_pps_mult1',
            'Incoming TCP traffic speed in packets per second. Mult1.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_tcp_traffic_pps_mult1)

        self.metric_incoming_tcp_traffic_pps_mult2 = GaugeMetricFamily(
            'kdp_incoming_tcp_traffic_pps_mult2',
            'Incoming TCP traffic speed in packets per second. Mult2.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_tcp_traffic_pps_mult2)            

        self.metric_incoming_tcp_traffic_pps = GaugeMetricFamily(
            'kdp_incoming_tcp_traffic_pps',
            'Incoming TCP traffic speed in packets per second. pps.',
            labels=['resource','type'])
        self.metrics.append(self.metric_incoming_tcp_traffic_pps)


        ## HTTP. Number of requests
        self.metric_http_hits_rate_direction = GaugeMetricFamily(
            'kdp_http_hits_rate_direction',
            'HTTP. Number of requests. Direction.',
            labels=['resource','type'])
        self.metrics.append(self.metric_http_hits_rate_direction)                      

        self.metric_http_hits_rate_threshold = GaugeMetricFamily(
            'kdp_http_hits_rate_threshold',
            'HTTP. Number of requests. Threshold.',
            labels=['resource','type'])
        self.metrics.append(self.metric_http_hits_rate_threshold)            

        self.metric_http_hits_rate_mult1 = GaugeMetricFamily(
            'kdp_http_hits_rate_mult1',
            'HTTP. Number of requests. Mult1.',
            labels=['resource','type'])
        self.metrics.append(self.metric_http_hits_rate_mult1)

        self.metric_http_hits_rate_mult2 = GaugeMetricFamily(
            'kdp_http_hits_rate_mult2',
            'HTTP. Number of requests. Mult2.',
            labels=['resource','type'])
        self.metrics.append(self.metric_http_hits_rate_mult2)            

        self.metric_http_hits_rate = GaugeMetricFamily(
            'kdp_http_hits_rate',
            'HTTP. Number of requests. hits/sec.',
            labels=['resource','type'])
        self.metrics.append(self.metric_http_hits_rate)                                     


        try:
            for l in param_list:
                for d in param_data:
                    if l.id == d.unit_check_id and d.value is not None:
                        if d.type == 0:
                            dtype = 'dirty'
                        elif d.type == 2:
                            dtype = 'clean'
                        else:
                            dtype = 'N/A'

                        if l.short_name == 'Number of IPs':
                            self.metric_ip_rate_direction.add_metric(
                                [self.resource_name,dtype], l.direction)
                            self.metric_ip_rate_threshold.add_metric(
                                [self.resource_name,dtype], d.threshold)
                            self.metric_ip_rate_mult1.add_metric(
                                [self.resource_name,dtype], d.mult1)
                            self.metric_ip_rate_mult2.add_metric(
                                [self.resource_name,dtype], d.mult2)
                            self.metric_ip_rate.add_metric(
                                [self.resource_name,dtype], d.value)
                        elif l.short_name == 'SYN packets':
                            self.metric_syn_packets_direction.add_metric(
                                [self.resource_name,dtype], l.direction)
                            self.metric_syn_packets_threshold.add_metric(
                                [self.resource_name,dtype], d.threshold)
                            self.metric_syn_packets_mult1.add_metric(
                                [self.resource_name,dtype], d.mult1)
                            self.metric_syn_packets_mult2.add_metric(
                                [self.resource_name,dtype], d.mult2)
                            self.metric_syn_packets.add_metric(
                                [self.resource_name,dtype], d.value)
                        elif l.short_name == 'SYN rating':
                            self.metric_syn_rating_direction.add_metric(
                                [self.resource_name,dtype], l.direction)
                            self.metric_syn_rating_threshold.add_metric(
                                [self.resource_name,dtype], d.threshold)
                            self.metric_syn_rating_mult1.add_metric(
                                [self.resource_name,dtype], d.mult1)
                            self.metric_syn_rating_mult2.add_metric(
                                [self.resource_name,dtype], d.mult2)
                            self.metric_syn_rating.add_metric(
                                [self.resource_name,dtype], d.value)
                        elif l.short_name == 'Incoming traffic in bps':
                            self.metric_incoming_traffic_bps_direction.add_metric(
                                [self.resource_name,dtype], l.direction)
                            self.metric_incoming_traffic_bps_threshold.add_metric(
                                [self.resource_name,dtype], d.threshold)
                            self.metric_incoming_traffic_bps_mult1.add_metric(
                                [self.resource_name,dtype], d.mult1)
                            self.metric_incoming_traffic_bps_mult2.add_metric(
                                [self.resource_name,dtype], d.mult2)
                            self.metric_incoming_traffic_bps.add_metric(
                                [self.resource_name,dtype], d.value)
                        elif l.short_name == 'Incoming traffic in pps':
                            self.metric_incoming_traffic_pps_direction.add_metric(
                                [self.resource_name,dtype], l.direction)
                            self.metric_incoming_traffic_pps_threshold.add_metric(
                                [self.resource_name,dtype], d.threshold)
                            self.metric_incoming_traffic_pps_mult1.add_metric(
                                [self.resource_name,dtype], d.mult1)
                            self.metric_incoming_traffic_pps_mult2.add_metric(
                                [self.resource_name,dtype], d.mult2)
                            self.metric_incoming_traffic_pps.add_metric(
                                [self.resource_name,dtype], d.value)
                        elif l.short_name == 'Outgoing traffic in bps':
                            self.metric_outgoing_traffic_bps_direction.add_metric(
                                [self.resource_name,dtype], l.direction)
                            self.metric_outgoing_traffic_bps_threshold.add_metric(
                                [self.resource_name,dtype], d.threshold)
                            self.metric_outgoing_traffic_bps_mult1.add_metric(
                                [self.resource_name,dtype], d.mult1)
                            self.metric_outgoing_traffic_bps_mult2.add_metric(
                                [self.resource_name,dtype], d.mult2)
                            self.metric_outgoing_traffic_bps.add_metric(
                                [self.resource_name,dtype], d.value)
                        elif l.short_name == 'Outgoing traffic in pps':
                            self.metric_outgoing_traffic_pps_direction.add_metric(
                                [self.resource_name,dtype], l.direction)
                            self.metric_outgoing_traffic_pps_threshold.add_metric(
                                [self.resource_name,dtype], d.threshold)
                            self.metric_outgoing_traffic_pps_mult1.add_metric(
                                [self.resource_name,dtype], d.mult1)
                            self.metric_outgoing_traffic_pps_mult2.add_metric(
                                [self.resource_name,dtype], d.mult2)
                            self.metric_outgoing_traffic_pps.add_metric(
                                [self.resource_name,dtype], d.value)
                        elif l.short_name == 'Incoming ICMP traffic':
                            self.metric_incoming_icmp_traffic_pps_direction.add_metric(
                                [self.resource_name,dtype], l.direction)
                            self.metric_incoming_icmp_traffic_pps_threshold.add_metric(
                                [self.resource_name,dtype], d.threshold)
                            self.metric_incoming_icmp_traffic_pps_mult1.add_metric(
                                [self.resource_name,dtype], d.mult1)
                            self.metric_incoming_icmp_traffic_pps_mult2.add_metric(
                                [self.resource_name,dtype], d.mult2)
                            self.metric_incoming_icmp_traffic_pps.add_metric(
                                [self.resource_name,dtype], d.value)
                        elif l.short_name == 'Incoming TCP traffic':
                            self.metric_incoming_tcp_traffic_pps_direction.add_metric(
                                [self.resource_name,dtype], l.direction)
                            self.metric_incoming_tcp_traffic_pps_threshold.add_metric(
                                [self.resource_name,dtype], d.threshold)
                            self.metric_incoming_tcp_traffic_pps_mult1.add_metric(
                                [self.resource_name,dtype], d.mult1)
                            self.metric_incoming_tcp_traffic_pps_mult2.add_metric(
                                [self.resource_name,dtype], d.mult2)
                            self.metric_incoming_tcp_traffic_pps.add_metric(
                                [self.resource_name,dtype], d.value)
                        elif l.short_name == 'HTTP. Requests':
                            self.metric_http_hits_rate_direction.add_metric(
                                [self.resource_name,dtype], l.direction)
                            self.metric_http_hits_rate_threshold.add_metric(
                                [self.resource_name,dtype], d.threshold)
                            self.metric_http_hits_rate_mult1.add_metric(
                                [self.resource_name,dtype], d.mult1)
                            self.metric_http_hits_rate_mult2.add_metric(
                                [self.resource_name,dtype], d.mult2)
                            self.metric_http_hits_rate.add_metric(
                                [self.resource_name,dtype], d.value)
                        else:
                            pass
                        
        except Exception as e:
            self.logger.error(f'{self.resource_name}: measured_parameters failed with: {e}')


def handle(req):
    """handle a request to the function
    Args:
        req (str): request body
    """

    obj = Collector()
    REGISTRY.register(obj)

    # Unregister default metrics
    REGISTRY.unregister(PROCESS_COLLECTOR)
    REGISTRY.unregister(PLATFORM_COLLECTOR)
    REGISTRY.unregister(GC_COLLECTOR)    
    
    return obj.generate_latest_scrape().decode('utf-8')