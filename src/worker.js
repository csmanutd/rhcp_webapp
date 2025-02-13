export default {
    async fetch(request, env, ctx) {
        return await handleRequest(request, env);
    }
};
  
async function handleRequest(request, env) {
    // 将 allowedOrigins 移到函数内部
    const allowedOrigins = [
        ...(env?.ALLOWED_ORIGINS || '').split(',').filter(Boolean),
        'http://localhost:8000',       // 本地开发环境
        'http://localhost:8787',       // Wrangler 本地开发服务器
        'http://127.0.0.1:8000',
        'http://127.0.0.1:8787'
    ];

    const origin = request.headers.get('Origin');

    // 如果没有 Origin 头或来源不在允许列表中，返回 403
    if (!origin || !allowedOrigins.includes(origin)) {
        return new Response('CORS Not Allowed', { 
            status: 403,
            headers: {
                'Content-Type': 'text/plain',
                'Access-Control-Allow-Origin': origin || '*',
            }
        });
    }

    if (request.method === 'OPTIONS') {
        return handleOptions(request);
    }

    try {
        if (request.method === 'POST') {
            // 接收并处理上传的文件
            const formData = await request.formData();
            const reportFile = formData.get('report');
            const rulesFile = formData.get('rules');
  
            if (!reportFile || !rulesFile) {
                return corsResponse('Both report and rules CSV files are required.', 400, origin);
            }
  
            const reportCSV = await reportFile.text();
            const reportFileName = reportFile.name;
            const rulesCSV = await rulesFile.text();
  
            const reportData = parseCSV(reportCSV);
            const rulesData = parseCSV(rulesCSV);
  
            // 合并 CSV 数据
            const mergedData = mergeCSVData(reportData, rulesData);
  
            // 返回结果
            return corsResponse(mergedData, 200, origin, {
                'Content-Type': 'application/json'
            }, reportFileName);
        }
  
        // 处理 GET 请求
        return corsResponse('Send CSV files via POST request.', 200, origin);
    } catch (error) {
        console.error('Error processing request:', error);
        return corsResponse('Internal Server Error: ' + error.message, 500, origin);
    }
}
  
async function handleOptions(request) {
    const origin = request.headers.get('Origin');
    
    if (!origin || !allowedOrigins.includes(origin)) {
        return new Response('CORS Not Allowed', { 
            status: 403,
            headers: {
                'Access-Control-Allow-Origin': origin || '*', // 确保返回 CORS 头
            }
        });
    }

    return new Response(null, {
        status: 204,
        headers: {
            'Access-Control-Allow-Origin': origin,
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '86400',
            'Access-Control-Allow-Credentials': 'true',
        },
    });
}
  
function corsResponse(body, status = 200, origin, additionalHeaders = {}, reportFileName) {
    const headers = {
        'Access-Control-Allow-Origin': origin,
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Access-Control-Allow-Credentials': 'true',
        'Vary': 'Origin',
        ...additionalHeaders
    };

    if (typeof body === 'object') {
        headers['Content-Type'] = 'application/json';
        body = JSON.stringify(body);
    }

    if (reportFileName && headers['Content-Type'] === 'text/csv') {
        const fileName = reportFileName.replace('.csv', '_plus.csv');
        headers['Content-Disposition'] = `attachment; filename="${fileName}"`;
    }

    return new Response(body, { status, headers });
}
  
function parseCSV(csvString) {
    const rows = csvString.trim().split('\n').map(row => row.split(','));
    return rows;
}
  
function mergeCSVData(reportData, rulesData) {
    const reportHeader = reportData[0];
    const rulesHeader = rulesData[0];
  
    // 需要移除的列
    const excludeColumns = ['ruleset_name', 'ruleset_href', 'rule_href'];
    const excludeIndexes = excludeColumns.map(col => rulesHeader.indexOf(col)).filter(idx => idx !== -1);
  
    const filteredRulesHeader = rulesHeader.filter((_, idx) => !excludeIndexes.includes(idx));
    const mergedHeader = reportHeader.concat(filteredRulesHeader);
    const mergedData = [mergedHeader];

    // 创建一个规则 Map，按忽略第四部分的格式存储
    const rulesMap = new Map(
        rulesData.slice(1).map(row => [
            normalizeHref(row[rulesHeader.indexOf('rule_href')]), // 使用标准化后的 href
            row.filter((_, idx) => !excludeIndexes.includes(idx)) // 过滤不需要的列
        ])
    );
  
    for (const reportRow of reportData.slice(1)) {
        const normalizedHref = normalizeHref(reportRow[reportHeader.indexOf('Rule HREF')]); // 标准化 Rule HREF
        const ruleMatch = rulesMap.get(normalizedHref) || [];
        mergedData.push(reportRow.concat(ruleMatch));
    }
  
    // 添加数据处理逻辑，为可视化准备数据
    const visualData = {
        rulesets: new Map()
    };

    for (const row of mergedData.slice(1)) {
        const rulesetName = row[mergedHeader.indexOf('Ruleset Name')];
        const rulesetScope = row[mergedHeader.indexOf('ruleset_scope')];
        const srcLabels = row[mergedHeader.indexOf('src_labels')];
        const srcIplists = row[mergedHeader.indexOf('src_iplists')];
        const dstLabels = row[mergedHeader.indexOf('dst_labels')];
        const dstIplists = row[mergedHeader.indexOf('dst_iplists')];
        const hitCount = row[mergedHeader.indexOf('Rule Hit Count')] || '0';
        // 添加新字段
        const unscopedConsumers = row[mergedHeader.indexOf('unscoped_consumers')] === 'TRUE' || 
                                 row[mergedHeader.indexOf('unscoped_consumers')] === 'true';
        const srcAllWorkloads = row[mergedHeader.indexOf('src_all_workloads')] === 'TRUE' || 
                               row[mergedHeader.indexOf('src_all_workloads')] === 'true';
        const dstAllWorkloads = row[mergedHeader.indexOf('dst_all_workloads')] === 'TRUE' || 
                               row[mergedHeader.indexOf('dst_all_workloads')] === 'true';
        const srcLabelsExclusions = row[mergedHeader.indexOf('src_labels_exclusions')] || '';
        const srcLabelGroups = row[mergedHeader.indexOf('src_label_groups')] || '';
        const srcLabelGroupsExclusions = row[mergedHeader.indexOf('src_label_groups_exclusions')] || '';
        const dstLabelsExclusions = row[mergedHeader.indexOf('dst_labels_exclusions')] || '';
        const dstLabelGroups = row[mergedHeader.indexOf('dst_label_groups')] || '';
        const dstLabelGroupsExclusions = row[mergedHeader.indexOf('dst_label_groups_exclusions')] || '';

        if (!visualData.rulesets.has(rulesetName)) {
            visualData.rulesets.set(rulesetName, {
                scope: rulesetScope,
                rules: []
            });
        }

        visualData.rulesets.get(rulesetName).rules.push({
            srcLabels: srcLabels || '',
            srcIplists: srcIplists || '',
            dstLabels: dstLabels || '',
            dstIplists: dstIplists || '',
            hitCount: hitCount,
            unscopedConsumers: unscopedConsumers,
            srcAllWorkloads: srcAllWorkloads,
            dstAllWorkloads: dstAllWorkloads,
            srcLabelsExclusions: srcLabelsExclusions,
            srcLabelGroups: srcLabelGroups,
            srcLabelGroupsExclusions: srcLabelGroupsExclusions,
            dstLabelsExclusions: dstLabelsExclusions,
            dstLabelGroups: dstLabelGroups,
            dstLabelGroupsExclusions: dstLabelGroupsExclusions
        });
    }

    // 将可视化数据添加到响应中
    return {
        csvData: mergedData,
        visualData: Object.fromEntries(visualData.rulesets)
    };
}
  
function normalizeHref(href) {
    // 提取从 "rule_sets" 开始的部分，忽略第四部分
    const parts = href.split('/');
    const ruleSetsIndex = parts.indexOf('rule_sets');
    return ruleSetsIndex !== -1 ? parts.slice(ruleSetsIndex).join('/') : href;
}
  
function convertToCSV(data) {
    return data.map(row => row.join(',')).join('\n');
}