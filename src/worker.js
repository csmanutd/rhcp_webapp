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
        return handleOptions(request, allowedOrigins);
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
            
            // 检查是否有错误
            if (mergedData.error) {
                return corsResponse({
                    success: false,
                    error: mergedData.error,
                    details: {
                        missingColumn: mergedData.missingColumn,
                        fileType: mergedData.fileType
                    }
                }, 400, origin, {
                    'Content-Type': 'application/json'
                });
            }
            
            // 返回结果
            return corsResponse({
                success: true,
                ...mergedData
            }, 200, origin, {
                'Content-Type': 'application/json'
            }, reportFileName);
        }
  
        // 处理 GET 请求
        return corsResponse('Send CSV files via POST request.', 200, origin);
    } catch (error) {
        console.error('Error processing request:', error);
        return corsResponse({
            success: false,
            error: 'Internal Server Error: ' + error.message
        }, 500, origin, {
            'Content-Type': 'application/json'
        });
    }
}
  
async function handleOptions(request, allowedOrigins) {
    const origin = request.headers.get('Origin');
    
    if (!origin || !allowedOrigins.includes(origin)) {
        return new Response('CORS Not Allowed', { 
            status: 403,
            headers: {
                'Access-Control-Allow-Origin': origin || '*',
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
    // 验证数据格式
    if (!reportData || !reportData.length || !reportData[0]) {
        return { error: "Invalid report CSV format. The file appears to be empty or malformed." };
    }
    
    if (!rulesData || !rulesData.length || !rulesData[0]) {
        return { error: "Invalid rules CSV format. The file appears to be empty or malformed." };
    }
    
    const reportHeader = reportData[0];
    const rulesHeader = rulesData[0];
    
    // 检查必要的列是否存在
    const ruleHrefIndex = reportHeader.indexOf('Rule HREF');
    if (ruleHrefIndex === -1) {
        return { 
            error: "Required column 'Rule HREF' is missing in the report CSV file. Please ensure your report contains this column.",
            missingColumn: "Rule HREF",
            fileType: "report"
        };
    }
    
    const ruleHrefRulesIndex = rulesHeader.indexOf('rule_href');
    if (ruleHrefRulesIndex === -1) {
        return { 
            error: "Required column 'rule_href' is missing in the rules CSV file. Please ensure your rules export contains this column.",
            missingColumn: "rule_href",
            fileType: "rules"
        };
    }
    
    // 需要移除的列
    const excludeColumns = ['ruleset_name', 'ruleset_href', 'rule_href'];
    const excludeIndexes = excludeColumns.map(col => rulesHeader.indexOf(col)).filter(idx => idx !== -1);
  
    const filteredRulesHeader = rulesHeader.filter((_, idx) => !excludeIndexes.includes(idx));
    const mergedHeader = reportHeader.concat(filteredRulesHeader);
    const mergedData = [mergedHeader];

    // 创建规则Map
    const rulesMap = new Map();
    
    if (ruleHrefRulesIndex !== -1) {
        rulesData.slice(1).forEach(row => {
            if (row && row[ruleHrefRulesIndex]) {
                const normalizedHref = normalizeHref(row[ruleHrefRulesIndex]);
                rulesMap.set(normalizedHref, row.filter((_, idx) => !excludeIndexes.includes(idx)));
            }
        });
    }
  
    // 处理报告数据
    for (const reportRow of reportData.slice(1)) {
        // 如果Rule HREF列不存在或该行没有值，则添加空匹配
        if (ruleHrefIndex === -1 || !reportRow[ruleHrefIndex]) {
            mergedData.push(reportRow.concat(Array(filteredRulesHeader.length).fill('')));
            continue;
        }
        
        // 正常处理有Rule HREF的情况
        const normalizedHref = normalizeHref(reportRow[ruleHrefIndex]);
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
    if (!href || typeof href !== 'string') return '';
    
    // 提取从 "rule_sets" 开始的部分，忽略第四部分
    const parts = href.split('/');
    const ruleSetsIndex = parts.indexOf('rule_sets');
    return ruleSetsIndex !== -1 ? parts.slice(ruleSetsIndex).join('/') : href;
}
  
function convertToCSV(data) {
    return data.map(row => row.join(',')).join('\n');
}