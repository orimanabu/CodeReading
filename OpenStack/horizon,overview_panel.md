# お題: Compute - OverviewパネルのLimit Summaryのところで、"Instance Used X of Y"のXがどこから来ているか

見るところ:

- /usr/share/openstack-dashboard ($dashboard)
- /usr/lib/python2.7/site-packages/horizon ($horizon)

## デバッグプリントしたいとき
```
```


## とりあえずgrep
'Limit Summary'でgrepする

$horizon/templates/horizon/common/_limit_summary.html がページのテンプレートっぽい

```
  <h3 class="quota-heading">{% trans "Limit Summary" %}</h3>
    <div class="d3_quota_bar">
      <div class="d3_pie_chart_usage" data-used="{% quotapercent usage.limits.totalInstancesUsed usage.limits.maxTotalInstances %}"></div>
      <strong>{% trans "Instances" %} <br />
        {% blocktrans with used=usage.limits.totalInstancesUsed|intcomma available=usage.limits.maxTotalInstances|quotainf|intcomma %}Used <span> {{ used }} </span> of <span> {{ available }} </span>{% endblocktrans %}
      </strong>
    </div>
```

usage.limitsがクラス？

totalInstanceUsedがXの値っぽい

## 見た目
$dashboard/openstack_dashboard/dashboards/project/overview がこのパネルっぽい

view.pyを見ると、ここかな

```
class ProjectOverview(usage.UsageView):
```

親クラスを見ることにする

## usage.UsageView
$dashboard/openstack_dashboard/usage/view.py

self.usage_classはbase.UsageBaseのサブクラスっぽい


## base.UsageBase
- UsageBase.get_limits() @$dashboard/openstack_dashboard/usage/base.py

  - api.nova.tenant_absolute_limits()を呼んでいる

## Nova API call
- tenant_absolute_limits() @$dashboard/api/nova.py

```
limits = novaclient(request).limits.get(reserved=reserved).absolute
```

## Nova client
- Client.\_\_init\_\_() @novaclient/v2/client.py

```
        self.limits = limits.LimitsManager(self)
```

## LimitsManager
- LimitsManager.get() @novaclient/v2/limits.py

"/limits"をREST API コールしているっぽい

## Nova controller
"totalInstancesUsed"でgrepする

- UsedLimitsController.index() @nova/api/openstack/compute/contrib/used_limits.py

"instances"のQuota情報がここの数字っぽい


## 結論

quota_usagesテーブルのresourceカラムがinstancesな行のin_useの数値
