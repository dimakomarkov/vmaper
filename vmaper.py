import os
import nmap
import csv
import pandas as pd
import numpy as np
import time
from pandas import concat
from nessrest import ness6rest
from openvas_lib import VulnscanManager, VulnscanException

def nmap_scan_parser(mas_ip):

    try:
        nm = nmap.PortScanner()
    except nmap.PortScannerError:
        print('Nmap not found', sys.exc_info()[0])
        sys.exit(1)
    except:
        print("Unexpected error:", sys.exc_info()[0])
        sys.exit(1)

    nm.scan(hosts=mas_ip, arguments='-A -T4')

    f = open('temp_data_1.csv', 'w')

    f.write(nm.csv())
    f.close()

    data = pd.read_csv('temp_data_1.csv', sep = ';')
    data.drop(['hostname',
               'hostname_type',
               'protocol',
               'extrainfo',
               'reason',
               'conf',
               'cpe'],
              axis='columns', inplace=True)
    data.drop_duplicates()
    data.to_csv('temp_data.csv')

def get_round_data():
    round_data = pd.read_csv('temp_data.csv', sep = ',')
    round_data.drop(round_data.columns[[0]],
                    axis='columns',
                    inplace = True)
    round_data.drop_duplicates()
    return round_data

def get_repo_data():
    repo_data = pd.read_csv('repo_data.csv',
                            sep = ',')
    repo_data = pd.concat([repo_data,
                           pd.DataFrame(columns = ['active_now'])])
    repo_data[['active_now']] = [0]
    repo_data.drop(repo_data.columns[[0, 1]],
                   axis='columns',
                   inplace=True)
    return repo_data

events = ('new_host',
          'known_host_is_active_again',
          'host_was_active',
          'host_was_lost',
          'new_port',
          'port_that_appeared_was_previously_active',
          'the_service_has_changed_on_the_port',
          'service_version_has_changed',
          'port_was_lost')

def log_writer(ip, port, num_event):
    f = open('logs.txt', 'a')
    print(time.strftime("%Y-%m-%d-%H.%M.%S", time.localtime()) +
          '---' + ip+ '--port:' + port + '---' + events[num_event],
          file = f)
    f.close()

def log_writer_2(ip):
    f = open('logs.txt', 'a')
    print(time.strftime("%Y-%m-%d-%H.%M.%S", time.localtime()) +
          '---'+ip+'is_similar_to_the_previously_active_host',
          file = f)
    f.close()

def proto_finder(ip, target, field, measure):
    field.drop(field.columns[[-1, -2]], axis='columns', inplace=True)
    t = target.values.tolist()
    s_=0
    n_=0
    for i in pd.unique(field['host']).tolist():
        f = field[field['host'] == i].drop(['host']).values.tolist()
        for j in range(len(t)):
            if (t[j] in f):
                s_ = s_ + 1
            else:
                n_ = n_ + 1
        mes = s_ / (s_ + n_)
        if mes >= measure:
            log_writer_2(ip)
        s_=0
        n_=0

def port_correlator(df1, df2):
    a = df1.values.tolist()
    b = df2.values.tolist()
    c = []
    d = []

    for i in range(len(a)):
        if not (a[i] in b):
            c.append(a[i])

    for j in range(len(b)):
        if not (b[i] in a):
            d.append(a[i])

    cn = np.asarray(c, dtype=np.float32)
    dn = np.asarray(d, dtype=np.float32)

    if cn.shape[0] > 0:
        f = open('logs.txt', 'a')
        for i in range(cn.shape[0]):
            print(
                time.strftime("%Y-%m-%d-%H.%M.%S", time.localtime()) +
                '---'+cn[i][0]+
                '---'+cn[i][1]+'---port_opened', file = f)
        f.close()

    if dn.shape[0] > 0:
        f = open('logs.txt', 'a')
        for i in range(dn.shape[0]):
            print(
                time.strftime("%Y-%m-%d-%H.%M.%S", time.localtime()) +
                '---'+dn[i][0]+'---'+dn[i][1]+'---port_was_lost_or_closed',
                file = f)
        f.close()

def lost_host(uni_round_hosts, uni_repo_hosts):
    round_d = np.array(uni_round_hosts)
    repo_d = np.array(uni_repo_hosts)
    for i in range(repo_d):
        if not (repo_d[i] in round_d):
            log_writer(repo_d[i],0,3)

def round_conversion(round_num, repo_num, metric_matr):
    for i in range(len(repo_num)):
        if repo_num[i] in round_num:
            repo_num.remove(repo_num[i])

    if (len(repo_num) > 0) & (len(round_num) > 0):
        for i in range(len(repo_num)):
            for j in range(len(round_num)):
                if (all(np.array(repo_num[i][:-1]) == np.array(round_num[j][:-1])) &
                    (repo_num[i][-1] == 0) & (round_num[j][-1] == 1)):
                    repo_num.remove(repo_num[i])

    if (len(repo_num) > 0) & (len(round_num) > 0):
        for i in range(len(repo_num)):
            for j in range(len(round_num)):
                if ((repo_num[i] != round_num[j]) &
                    (repo_num[i][0] == round_num[j][0]) &
                    (repo_num[i][1] == round_num[j][1]) &
                    (repo_num[i][-1] == 1) &
                    (round_num[j][-1] == 1)):
                    repo_num[i][-1] = 0
                    round_num.append(repo_num[i])
                    repo_num.remove(repo_num[i])

    if (len(repo_num) > 0) & (len(round_num) > 0):
        for i in range(len(repo_num)):
            if (repo_num[i][-1] == 1) &  (not(repo_num[i] in round_num)):
                repo_num[i][-1] = 0
                round_num.append(repo_num[i])
                repo_num.remove(repo_num[i])

    return round_num + repo_num

def put_repo_data(data):
    data = pd.DataFrame({'host': data[:, 0], 'port': data[:, 1],
                         'name': data[:, 2], 'state': data[:, 3],
                         'product': data[:, 4], 'version': data[:, 5],
                         'active': data[:, 6]})
    os.remove("repo_data.csv")
    data.to_csv('repo_data.csv', index=False, sep = ',')

def calc_metrics(round_data, repo_data, metric_matrix):
    for i in range(metric_matrix.shape[0]):
        if repo_data[repo_data['host'] == round_data.iloc[i][0]].shape[0] > 0:
            if repo_data[(repo_data['host'] == round_data.iloc[i][0]) &
                         (repo_data['active'] == 1)].shape[0] > 0:
                metric_matrix[i][0] = 0.5
            else:
                metric_matrix[i][0] = 0.75
            if repo_data[(repo_data['host'] == round_data.iloc[i][0]) &
                         (repo_data['port'] == round_data.iloc[i][1])].shape[0] < 1:
                metric_matrix[i][1] = 0.25
            else:
                if repo_data[(repo_data['host'] == round_data.iloc[i][0]) &
                             (repo_data['port'] == round_data.iloc[i][1]) &
                             (repo_data['active'] == 1)].shape[0] > 0:
                    metric_matrix[i][1] = 1
                else:
                    metric_matrix[i][1] = 0.5
                if repo_data[(repo_data['host'] == round_data.iloc[i][0]) &
                             (repo_data['port'] == round_data.iloc[i][1]) &
                             (repo_data['active'] == 1)]['product'] == round_data.iloc[i][4]:
                    if repo_data[(repo_data['host'] == round_data.iloc[i][0]) &
                                 (repo_data['port'] == round_data.iloc[i][1]) &
                                 (repo_data['active'] == 1)]['version'] == round_data.iloc[i][5]:
                        metric_matrix[i][2] = 0.5
                    else:
                        metric_matrix[i][2] = 0.75
                else:
                    metric_matrix[i][2] = 1
        else:
            metric_matrix[i][0] = 1
            metric_matrix[i][1] = 0.25
            metric_matrix[i][2] = 1
    return metric_matrix

def proc_metric(round_data, repo_data, metric_matrix):
    for i in range(metric_matrix.shape[0]):
        if (metric_matrix[i][0] == 1 &
            metric_matrix[i][1] == 0.25 &
            metric_matrix[i][2] == 1):
            log_writer(round_data.iloc[i][0],
                       round_data.iloc[i][1], 0)
    for i in range(metric_matrix.shape[0]):
        if metric_matrix[i][0] == 0.5:
            log_writer(round_data.iloc[i][0],
                       round_data.iloc[i][1], 2)
        elif metric_matrix[i][0] == 0.75:
            log_writer(round_data.iloc[i][0],
                       round_data.iloc[i][1], 1)

        if metric_matrix[i][1] == 0.25:
            log_writer(round_data.iloc[i][0],
                       round_data.iloc[i][1], 4)
        elif metric_matrix[i][1] == 0.5:
            log_writer(round_data.iloc[i][0],
                       round_data.iloc[i][1], 5)
        if metric_matrix[i][2] == 0.75:
            log_writer(round_data.iloc[i][0],
                       round_data.iloc[i][1], 7)
        else:
            if (metric_matrix[i][2] == 1) & (metric_matrix[i][0] != 1):
                log_writer(round_data.iloc[i][0],
                           round_data.iloc[i][1], 6)

        proto_finder(round_data.iloc[i][0],
                     round_data[round_data['host'] == round_data.iloc[i][0]].iloc[:, 1:6],
                     repo_data[repo_data['active'] == 0], 0.75)

def main_logs(str_):
    f = open('logs.txt', 'a')
    print(time.strftime("%Y-%m-%d-%H.%M.%S", time.localtime())+'---'+str_, file = f)
    f.close()

def nessus_intagrator(hosts):

    scan = ness6rest.Scanner(url="https://192.168.25.125:8834",
                             login="admin",
                             password="P@ssw0rd",
                             insecure=True)

    for h in range(len(hosts)):
        scan.scan_add(targets=hosts[i])
        scan.scan_run()

def openvas_integrator(hosts):

    try:
        scanner = VulnscanManager("192.168.25.125",
                                  "admin",
                                  "admin",
                                  4000,
                                  300)
    except VulnscanException as e:
        print("Error:")
        print(e)

    for h in range(len(hosts)):
        scan_id, target_id = scanner.launch_scan(target = "127.0.0.1",
                                                 profile = "Full and fast")
#main()
print('Enter_range_of_IPs')
hosts = input()
main_logs('START_WORKING')
print('NEED_AN_INITIAL_SCAN(y/n)?')
ans = input()

if ans == 'y':
    nmap_scan_parser(hosts)
    first_round_data = pd.read_csv('temp_data.csv', sep = ',')
    first_round_data = pd.concat([first_round_data,
                                  pd.DataFrame(columns = ['active'])])
    first_round_data[['active']] = [1]
    first_round_data.to_csv('repo_data.csv')
    main_logs('ZERO_DATA_RECEIVED')

print('Enter_mode: singly(0)/auto(1)')
mode_flag = input()
mode_flag = int(mode_flag)

flag =True
time_delay_days = 3

while flag == True:

    nmap_scan_parser(hosts)

    round_data = get_round_data()
    repo_data = get_repo_data()

    metric_matrix = np.zeros((round_data.shape[0], 3),
                             dtype=np.float64)

    metric_matrix = calc_metrics(round_data,
                                 repo_data,
                                 metric_matrix)
    proc_metric(round_data, repo_data, metric_matrix)

    port_correlator(round_data[round_data['state'] == 'open'].iloc[:, 0:2],
                    repo_data[(repo_data['state'] == 'open') &
                              repo_data['active'] == 1].iloc[:, 0:2])

    lost_host(pd.unique(round_data['host']).tolist(),
              pd.unique(repo_data['host']).tolist())

    hosts_for_scan = []

    for i in range(metric_matrix):
        if ((metric_matrix[i][0] == 1) or
            (metric_matrix[i][0] == 0.75) or
            (metric_matrix[i][1] == 0.5) or
            (metric_matrix[i][1] == 0.25) or
            (metric_matrix[i][2] != 0)):
            host_for_scan.append(round_data.values[i][0])

    round_data = pd.concat([round_data, pd.DataFrame(columns = ['active'])])

    round_data[['active']] = [1]

    temp = round_conversion(round_data.values.tolist(),
                            repo_dat.drop(['active_now'],
                                          axis='columns',
                                          inplace=True).values.tolist(),
                            metric_matrix)
    put_repo_data(temp)


    if mode_flag == 0:
        break

    time.sleep(86400 * time_delay_days)
